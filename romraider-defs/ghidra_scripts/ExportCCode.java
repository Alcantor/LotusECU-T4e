//@category Export
//@menupath Tools.Export.C Code
//@description Export the current program to a single monolithic .c file, byte-for-byte matching
//             how black91.c/boot08.c/hc08.c were produced (equivalent to File > Export Program...
//             with format "C/C++", header file disabled, "Eliminate unreachable code" off).

import java.io.File;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.CppExporter;

public class ExportCCode extends GhidraScript {

	@Override
	public void run() throws Exception {
		File outputFile = askFile("Export C Code", "Export");
		if (outputFile == null) return;

		DecompileOptions options = new DecompileOptions();
		options.setCommentStyle(DecompileOptions.CommentStyleEnum.CPPStyle);
		options.setEliminateUnreachable(false);

		CppExporter exporter = new CppExporter(options, false, true, true, true, true, "");
		boolean ok = exporter.export(outputFile, currentProgram, null, monitor);
		if (ok) {
			println("Exported " + currentProgram.getName() + " to " + outputFile.getAbsolutePath());
		} else {
			println("Export failed");
		}
	}
}
