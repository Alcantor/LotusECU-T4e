//@category OBD
//@menupath Tools.OBD.OBD2 Code Configuration
//@description Analyzes all calls to obd_set_dtc() and extracts OBD-II DTC codes from the function arguments. Automatically labels the configuration (CAL_obd_PXXXX) and creates individual labels for flags and counters (LEA_obd_PXXXX_flags, LEA_obd_PXXXX_engine_start_count, LEA_obd_PXXXX_warm_up_cycle_count).

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class OBD2CodeConfiguration extends GhidraScript {

	private final String OBD_SET_DTC_FUNNAME = "obd_set_dtc";

	private DataType u8OdbConfigType;
	private DataType uint8Type;
	private FunctionManager funcManager;
	private DecompInterface decompiler;
	private Function cachedFunc;
	private HighFunction cachedHighFunc;
	private Map<String, String> dtcDescriptions;

	private void setLabel(Address addr, String name) throws Exception {
		for (Symbol sym : currentProgram.getSymbolTable().getSymbols(addr))
			sym.delete();
		createLabel(addr, name, true);
	}

	private void extractArgInfo(final Reference ref) {
		final Address callAddr = ref.getFromAddress();
		final AddressSpace addrSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();

		// Get the function containing this call
		Function callingFunc = funcManager.getFunctionContaining(callAddr);
		if (callingFunc == null) {
			println("WARNING: Could not find function containing call at " + callAddr);
			return;
		}

		if (!callingFunc.equals(cachedFunc)) {
			DecompileResults decompResults = decompiler.decompileFunction(callingFunc, 30, monitor);
			if (!decompResults.decompileCompleted()) {
				println("WARNING: Decompilation failed for function at " + callingFunc.getEntryPoint());
				return;
			}
			cachedHighFunc = decompResults.getHighFunction();
			if (cachedHighFunc == null) {
				println("WARNING: No high function available at " + callAddr);
				return;
			}
			cachedFunc = callingFunc;
		}

		Iterator<PcodeOpAST> pcodeOps = cachedHighFunc.getPcodeOps(callAddr);
		while (pcodeOps.hasNext()) {
			PcodeOpAST pcodeOp = pcodeOps.next();
			if (pcodeOp.getOpcode() != PcodeOp.CALL) continue;

			long dtc_num;
			Address configAddr, dtcFlagsAddr, engineStartCounterAddr, warmUpCycleCounterAddr;
			String dtcCode;

			try {
				configAddr             = addrSpace.getAddress(pcodeOp.getInput(1).getDef().getInput(1).getOffset());
				dtcFlagsAddr           = addrSpace.getAddress(pcodeOp.getInput(2).getDef().getInput(1).getOffset());
				engineStartCounterAddr = addrSpace.getAddress(pcodeOp.getInput(3).getDef().getInput(1).getOffset());
				warmUpCycleCounterAddr = addrSpace.getAddress(pcodeOp.getInput(4).getDef().getInput(1).getOffset());

				final Varnode dtc_num_node = pcodeOp.getInput(5);
				if (!dtc_num_node.isConstant()) throw new Exception("DTC number is not a constant");
				dtc_num = dtc_num_node.getOffset();

				// The DTC Type argument exists only in T6 ECUs
				final Varnode dtc_type_node = pcodeOp.getInput(6);
				if (dtc_type_node != null) {
					if (!dtc_type_node.isConstant()) throw new Exception("DTC type is not a constant");
					dtcCode = String.format("%c%04X", "PCBU".charAt((int)dtc_type_node.getOffset()), dtc_num);
				} else {
					dtcCode = String.format("P%04d", dtc_num);
				}
			} catch (Exception e) {
				println("WARNING: Call at " + callAddr + " is not of type (4x deferred pointer, 1-2x constant): " + e.getMessage());
				break;
			}

			println(String.format("Adding %s symbols from call at %s in %s", dtcCode, callAddr, callingFunc.getName()));
			try {
				setLabel(configAddr,             "CAL_obd_" + dtcCode);
				String desc = dtcDescriptions.get(dtcCode);
				if (desc != null)
					currentProgram.getListing().setComment(configAddr, CodeUnit.EOL_COMMENT, desc);
				clearListing(configAddr, configAddr.add(u8OdbConfigType.getLength() - 1));
				createData(configAddr, u8OdbConfigType);
				setLabel(dtcFlagsAddr,           "LEA_obd_" + dtcCode + "_flags");
				clearListing(dtcFlagsAddr);
				createData(dtcFlagsAddr, uint8Type);
				setLabel(engineStartCounterAddr, "LEA_obd_" + dtcCode + "_engine_start_count");
				clearListing(engineStartCounterAddr);
				createData(engineStartCounterAddr, uint8Type);
				setLabel(warmUpCycleCounterAddr, "LEA_obd_" + dtcCode + "_warm_up_cycle_count");
				clearListing(warmUpCycleCounterAddr);
				createData(warmUpCycleCounterAddr, uint8Type);
			} catch (Exception e) {
				println("WARNING: " + e.getMessage());
			}
			break;
		}
	}

	@Override
	public void run() throws Exception {
		println("OBD-II Code Configuration Analysis");
		println("===================================\n");

		boolean isT6 = askYesNo("ECU Type", "Is this a T6 ECU? (Yes = u8_obd_config_t6, No = u8_obd_config)");
		String configTypePath = isT6 ? "/ECU/u8_obd_config_t6" : "/ECU/u8_obd_config";
		u8OdbConfigType = currentProgram.getDataTypeManager().getDataType(configTypePath);
		if (u8OdbConfigType == null) {
			println("ERROR: Data type '" + configTypePath + "' not found!");
			return;
		}
		uint8Type = currentProgram.getDataTypeManager().getDataType("/stdint.h/uint8_t");
		if (uint8Type == null) {
			println("ERROR: Data type 'uint8_t' not found!");
			return;
		}

		dtcDescriptions = new HashMap<>();
		try {
			java.io.File csvFile = askFile("Select OBD2-DTCs.csv", "Open");
			try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
				String line;
				br.readLine(); // skip header
				while ((line = br.readLine()) != null) {
					int comma = line.indexOf(',');
					if (comma < 0) continue;
					String code = line.substring(0, comma).trim();
					String desc = line.substring(comma + 1).trim();
					dtcDescriptions.merge(code, desc, (a, b) -> a.length() >= b.length() ? a : b);
				}
			}
			println("Loaded " + dtcDescriptions.size() + " DTC descriptions\n");
		} catch (ghidra.util.exception.CancelledException e) {
			println("No DTC descriptions CSV loaded, skipping comments\n");
		}

		funcManager = currentProgram.getFunctionManager();
		decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		Function targetFunc = null;
		for (final Function func : funcManager.getFunctions(true)) {
			if (func.getName().equals(OBD_SET_DTC_FUNNAME)) {
				targetFunc = func;
				break;
			}
		}
		if (targetFunc == null) {
			println("ERROR: Function 'obd_set_dtc' not found!");
			return;
		}

		println("Found function: " + targetFunc.getName() + " at " + targetFunc.getEntryPoint());
		println("Searching for all calls to this function...");

		final ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(targetFunc.getEntryPoint());

		int processedCount = 0;
		while (refIter.hasNext()) {
			extractArgInfo(refIter.next());
			processedCount++;
		}

		println("=================================");
		println("Processed " + processedCount + " calls");
		println("=================================");

		// Cleanup
		decompiler.dispose();
	}
}
