//@category Export
//@menupath Tools.Export.C Functions
//@description Export every function of the current program as one decompiled .c file per
//             function, in a single headless run. Headless arg: <outputDirectory>.
//             Each file starts with declarations of the global variables the function
//             references ("<type> <name>; // <address>" lines), then a blank line, then
//             an optional "// Called from:" block: one "// <caller> (N. call)" line per
//             call site to this function (N-th call of that caller to it), then the
//             decompiled code. The globals give type context per function
//             without needing to parse a monolithic export; the caller counts
//             distinguish identical bodies such as can_a_mbXX_unused mailboxes.

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class ExportCFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String dirPath = args.length >= 1 ? args[0] : null;
		if (dirPath == null) {
			dirPath = askString("Output directory", "Directory for the per-function .c files");
			if (dirPath == null) return;
		}

		File dir = new File(dirPath);
		if (!dir.exists() && !dir.mkdirs()) {
			printerr("Cannot create directory: " + dirPath);
			return;
		}

		DecompileOptions options = new DecompileOptions();
		options.setCommentStyle(DecompileOptions.CommentStyleEnum.CPPStyle);
		options.setEliminateUnreachable(false);

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.openProgram(currentProgram);
		int ok = 0, failed = 0;
		try {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.isThunk()) continue;
				if (monitor.isCancelled()) break;
				DecompileResults results = ifc.decompileFunction(f, 120, monitor);
				if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
					printerr("Decompilation failed for " + f.getName() + ": " +
						results.getErrorMessage());
					failed++;
					continue;
				}

				StringBuilder sb = new StringBuilder();
				sb.append("// Globals referenced by ");
				sb.append(f.getName());
				sb.append("():\n");
				globalDecls(results.getHighFunction(), sb);
				sb.append("\n");
				callerAnnotation(f, sb);
				sb.append(results.getDecompiledFunction().getC());

				File out = new File(dir, f.getName() + ".c");
				try (PrintWriter pw = new PrintWriter(new FileWriter(out))) {
					pw.print(sb.toString());
				}
				ok++;
			}
		}
		finally {
			ifc.dispose();
		}
		println("Exported " + ok + " functions to " + dir.getAbsolutePath() +
			" (" + failed + " failed)");
	}

	/**
	 * Build "<type> <name>; // <address>" lines for every global variable the
	 * decompiler resolved for this function, from the pcode global symbol map.
	 * Structured, so no false positives from local names or comment text; it
	 * may include globals optimized out of the printed body. Unlabeled data
	 * appears as its DAT_ address token, named symbols as their label; the
	 * type is the decompiler's resolved data type.
	 */
	private void globalDecls(HighFunction high, StringBuilder sb) {
		List<HighSymbol> syms = new ArrayList<>();
		Iterator<HighSymbol> it = high.getGlobalSymbolMap().getSymbols();
		while (it.hasNext()) {
			syms.add(it.next());
		}
		syms.sort((a, b) -> a.getStorage().getMinAddress().compareTo(b.getStorage().getMinAddress()));
		for (HighSymbol s : syms) {
			sb.append(s.getDataType().getName());
			sb.append(' ');
			sb.append(s.getName());
			sb.append("; // ");
			sb.append(s.getStorage().getMinAddress());
			sb.append('\n');
		}
	}

	/**
	 * Build a "// Called from:" block from the CALL references to this
	 * function: one "// <caller> (N. call)" line per call site, callers
	 * grouped in reference (address) order, the caller line repeated when it
	 * calls this function several times. N is the index of that call among
	 * the caller's calls to this function — an invariant across firmware
	 * variants that lets identical bodies (e.g. can_a_mbXX_unused mailboxes)
	 * be distinguished by who calls them and how often.
	 */
	private void callerAnnotation(Function f, StringBuilder sb) {
		ReferenceManager rm = currentProgram.getReferenceManager();
		ghidra.program.model.listing.FunctionManager fm = currentProgram.getFunctionManager();
		Map<Function, List<Address>> byCaller = new LinkedHashMap<>();
		for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
			if (!r.getReferenceType().isCall()) continue;
			Function caller = fm.getFunctionContaining(r.getFromAddress());
			if (caller == null) continue;
			byCaller.computeIfAbsent(caller, k -> new ArrayList<>()).add(r.getFromAddress());
		}
		if (byCaller.isEmpty()) return;

		sb.append("// Called from:\n");
		for (Map.Entry<Function, List<Address>> e : byCaller.entrySet()) {
			for (int i = 1; i <= e.getValue().size(); i++) {
				sb.append("// ");
				sb.append(e.getKey().getName());
				sb.append(" (");
				sb.append(i);
				sb.append(". call)\n");
			}
		}
	}
}
