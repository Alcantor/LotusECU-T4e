//@category Symbol
//@menupath Tools.Import.SymbolsFromCSV
//@description Rename functions and data from a CSV file. Supports FUN_/DAT_ generated names
//             (address extracted from hex suffix), existing labels (looked up by name), optional
//             type application, and optional EOL/function comment — whenever the column is present.

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ImportSymbolsFromCSV extends GhidraScript {

	/** Matches Ghidra-generated names: FUN_00123abc or DAT_00123abc */
	private static final Pattern GENERATED_NAME =
		Pattern.compile("^(FUN|DAT)_([0-9A-Fa-f]+)$");

	@Override
	public void run() throws Exception {
		File csvFile = askFile("Select CSV file", "Import");
		if (csvFile == null) return;

		int renamed = 0, typed = 0, commented = 0, errors = 0;

		try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
			String headerLine = br.readLine();
			if (headerLine == null) {
				printerr("Empty CSV file.");
				return;
			}

			String[] headers = parseCsvLine(headerLine);
			int colName    = findColumn(headers, "name", "original_name", "old_name");
			int colNewName = findColumn(headers, "new_name", "new name");
			int colType    = findColumn(headers, "type");
			int colComment = findColumn(headers, "comment", "description");

			if (colName < 0) {
				printerr("CSV must have a name column (name / original_name / old_name).");
				return;
			}
			if (colNewName < 0) {
				printerr("CSV must have a new_name column.");
				return;
			}

			println("Columns — name:" + colName + "  new_name:" + colNewName +
				"  type:" + (colType < 0 ? "absent" : String.valueOf(colType)) +
				"  comment:" + (colComment < 0 ? "absent" : String.valueOf(colComment)));
			println("");

			String line;
			int lineNum = 1;
			while ((line = br.readLine()) != null) {
				lineNum++;
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) continue;
				if (monitor.isCancelled()) break;

				String[] fields  = parseCsvLine(line);
				String name      = getField(fields, colName);
				String newName   = getField(fields, colNewName);
				String typeName  = getField(fields, colType);
				String comment   = getField(fields, colComment);

				if (name.isEmpty() || newName.isEmpty()) continue;

				try {
					Address addr = resolveAddress(name);
					if (addr == null) {
						printerr("Line " + lineNum + ": not found: " + name);
						errors++;
						continue;
					}

					Function func = getFunctionAt(addr);
					if (func != null) {
						/* ── Function ── */
						String old = func.getName();
						func.setName(newName, SourceType.USER_DEFINED);
						renamed++;
						println("F  " + old + "  ->  " + newName);
						if (!comment.isEmpty()) {
							func.setComment(comment);
							commented++;
						}
					} else {
						/* ── Data / label ── */
						SymbolTable symTab = currentProgram.getSymbolTable();
						Symbol sym = symTab.getPrimarySymbol(addr);
						String old = (sym != null) ? sym.getName() : addr.toString();
						if (sym != null) {
							sym.setName(newName, SourceType.USER_DEFINED);
						} else {
							symTab.createLabel(addr, newName, SourceType.USER_DEFINED);
						}
						renamed++;
						println("D  " + old + "  ->  " + newName);
						if (!typeName.isEmpty()) {
							if (applyType(addr, typeName)) typed++;
						}
						if (!comment.isEmpty()) {
							Listing listing = currentProgram.getListing();
							CodeUnit cu = listing.getCodeUnitAt(addr);
							if (cu != null) {
								cu.setComment(CodeUnit.EOL_COMMENT, comment);
								commented++;
							}
						}
					}
				} catch (Exception e) {
					printerr("Line " + lineNum + " (" + name + "): " + e.getMessage());
					errors++;
				}
			}
		}

		println("");
		println("=== Summary ===");
		println("Renamed:   " + renamed);
		println("Typed:     " + typed);
		println("Commented: " + commented);
		println("Errors:    " + errors);
	}

	/**
	 * Resolve an address from:
	 *   - a Ghidra-generated name  FUN_00123abc / DAT_00123abc  (hex suffix → address)
	 *   - an existing symbol name  (searched in the symbol table)
	 *   - an existing function name
	 */
	private Address resolveAddress(String name) {
		Matcher m = GENERATED_NAME.matcher(name);
		if (m.matches()) {
			long offset = Long.parseLong(m.group(2), 16);
			return toAddr(offset);
		}

		SymbolTable symTab = currentProgram.getSymbolTable();
		for (Symbol sym : symTab.getSymbols(name)) {
			return sym.getAddress();
		}

		Function func = getFunction(name);
		if (func != null) return func.getEntryPoint();

		return null;
	}

	/**
	 * Apply a data type at the given address.
	 * Supports array notation: uint8_t[16], int16_t[4][8], …
	 */
	private boolean applyType(Address addr, String typeName) {
		if (typeName.equalsIgnoreCase("function")) return false;

		DataType dt = resolveType(typeName);
		if (dt == null) {
			printerr("  Type not found: " + typeName);
			return false;
		}

		Listing listing = currentProgram.getListing();
		try {
			listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
			listing.createData(addr, dt);
			return true;
		} catch (Exception e) {
			printerr("  Cannot apply type " + typeName + " at " + addr + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Resolve a type name, building ArrayDataType wrappers for bracket notation.
	 * E.g. "int16_t[4][16]" → ArrayDataType(ArrayDataType(int16_t, 16), 4)
	 */
	private DataType resolveType(String typeName) {
		int bracket = typeName.indexOf('[');
		if (bracket < 0) return findBaseType(typeName);

		DataType base = findBaseType(typeName.substring(0, bracket).trim());
		if (base == null) return null;

		List<Integer> dims = new ArrayList<>();
		Matcher m = Pattern.compile("\\[(\\d+)\\]").matcher(typeName.substring(bracket));
		while (m.find()) dims.add(Integer.parseInt(m.group(1)));

		DataType dt = base;
		for (int i = dims.size() - 1; i >= 0; i--) {
			dt = new ArrayDataType(dt, dims.get(i), -1);
		}
		return dt;
	}

	/** Search for a base (non-array) type in the program and built-in type managers. */
	private DataType findBaseType(String name) {
		List<DataType> results = new ArrayList<>();

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		dtm.findDataTypes(name, results);
		if (!results.isEmpty()) return results.get(0);

		BuiltInDataTypeManager.getDataTypeManager().findDataTypes(name, results);
		if (!results.isEmpty()) return results.get(0);

		return null;
	}

	/** Case-insensitive column lookup; returns -1 if none of the candidates match. */
	private int findColumn(String[] headers, String... candidates) {
		for (int i = 0; i < headers.length; i++) {
			String h = headers[i].trim().toLowerCase();
			for (String c : candidates) {
				if (h.equals(c.toLowerCase())) return i;
			}
		}
		return -1;
	}

	/** Safe field getter — returns empty string for out-of-bounds or missing columns. */
	private String getField(String[] fields, int col) {
		if (col < 0 || col >= fields.length) return "";
		return fields[col].trim();
	}

	/** RFC-4180-compatible CSV line parser (handles quoted fields and escaped quotes). */
	private String[] parseCsvLine(String line) {
		List<String> fields = new ArrayList<>();
		StringBuilder sb = new StringBuilder();
		boolean inQuotes = false;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if (c == '"') {
				if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
					sb.append('"');
					i++;
				} else {
					inQuotes = !inQuotes;
				}
			} else if (c == ',' && !inQuotes) {
				fields.add(sb.toString());
				sb.setLength(0);
			} else {
				sb.append(c);
			}
		}
		fields.add(sb.toString());
		return fields.toArray(new String[0]);
	}
}
