//@category Symbol
//@menupath  Tools.Export.GNUSym
//@description Export user-defined symbols to a GNU-compatible .sym file

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExportGNUSym extends GhidraScript {

	/** Same validity test you used in Python */
	private static final Pattern VALID_NAME =
		Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");

	@Override
	public void run() throws Exception {

		/* Ask the user where to save the .sym file */
		File outputFile = askFile("Symbol File", "Save");
		if (outputFile == null) return;

		BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile));
		writer.write("# GNU Symbol File\n# Exported from Ghidra\n\n");

		SymbolTable symTab = currentProgram.getSymbolTable();
		SymbolIterator it = symTab.getAllSymbols(true);

		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol sym = it.next();
			if (sym.getSource() == SourceType.USER_DEFINED) {
				String name = sym.getName();
				if (VALID_NAME.matcher(name).matches()) {
					long offset = sym.getAddress().getOffset();
					writer.write(String.format("%s = 0x%x;\n", name, offset));
				}
			}
		}

		writer.close();
		println("User-defined symbols exported to " + outputFile.getAbsolutePath());
	}
}
