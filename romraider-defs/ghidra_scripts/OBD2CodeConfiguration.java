//@category OBD
//@menupath Tools.OBD.OBD2 Code Configuration
//@description Analyzes all calls to obd_ii_monitor_fail_transition() and extracts OBD-II DTC codes from the function arguments. Automatically labels the configuration (CAL_obd_ii_PXXXX) and creates individual labels for dtc_state, fail_counter, and pass_counter (LEA_obd_ii_PXXXX_dtc_state, LEA_obd_ii_PXXXX_fail_counter, LEA_obd_ii_PXXXX_pass_counter).

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.util.Iterator;

public class OBD2CodeConfiguration extends GhidraScript {

	private final String OBD_II_FAIL_FUNNAME = "obd_ii_monitor_fail_transition";

	/**
	 * Resolves a varnode to an actual memory address by tracing through P-code operations.
	 * Varnodes can exist in different address spaces (registers, stack, etc.) but may contain
	 * memory addresses as values. This method traces back to find the actual address value.
	 */
	private Address resolveVarnodeToAddress(Varnode vn, int depth) {
		if (depth > 20) {
			return null;
		}

		// If it's a constant, the offset IS the address value
		if (vn.isConstant()) {
			long addressValue = vn.getOffset();
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressValue);
		}

		// If it's in RAM address space, use the address directly
		if (vn.isAddress()) {
			return vn.getAddress();
		}

		// Otherwise, trace back through the defining operation
		PcodeOp def = vn.getDef();
		if (def == null) {
			// No definition - might be a function parameter or uninitialized value
			// Check if this varnode is in a register and has descendants that might reveal the value
			if (vn.isRegister()) {
				// For registers, we can't easily determine the value without dataflow analysis
				// This might be a parameter passed into the function
				return null;
			}
			return null;
		}

		if (def != null) {
			int opcode = def.getOpcode();

			// Special handling for PTRSUB/PTRADD - these operations add an offset to a base address
			// This is commonly used for struct member access like &struct.field
			// Ghidra sometimes uses PTRSUB(0, address) to represent a simple address value
			if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD) {
				if (def.getNumInputs() >= 2) {
					Varnode input0 = def.getInput(0); // Base address
					Varnode input1 = def.getInput(1); // Offset or actual address

					// Get the base address
					Address baseAddr = resolveVarnodeToAddress(input0, depth + 1);

					// Special case: PTRSUB(0, address) - the "offset" is actually the full address
					// This is Ghidra's way of representing &variable when there's no real base
					if (baseAddr != null && baseAddr.getOffset() == 0) {
						// Input[1] contains the actual address
						return resolveVarnodeToAddress(input1, depth + 1);
					}

					// If the base address is invalid/small and not 0, we can't resolve this
					if (baseAddr == null || baseAddr.getOffset() < 0x1000) {
						return null;
					}

					// Normal case: base + offset for actual struct member access
					// Get the offset - it might be a constant or need to be resolved
					long offset = 0;
					if (input1.isConstant()) {
						offset = input1.getOffset();
					} else {
						Address offsetAddr = resolveVarnodeToAddress(input1, depth + 1);
						if (offsetAddr != null) {
							offset = offsetAddr.getOffset();
						}
					}

					// Only apply the offset if it seems reasonable (< 256 bytes for struct member)
					if (offset < 256) {
						return baseAddr.add(offset);
					} else {
						return null;
					}
				}
			}

			// Handle LOAD operations - loading a value from memory
			// LOAD inputs: [0] = address space, [1] = address to load from
			if (opcode == PcodeOp.LOAD) {
				if (def.getNumInputs() > 1) {
					Varnode addrVarnode = def.getInput(1);
					// The address being loaded from might itself be a constant address
					Address loadAddr = resolveVarnodeToAddress(addrVarnode, depth + 1);
					if (loadAddr != null && loadAddr.getOffset() >= 0x1000) {
						// This is a valid address - try to read the value stored at this address
						// which should be the actual target address
						try {
							// Read a pointer-sized value from this address
							long value = currentProgram.getMemory().getInt(loadAddr) & 0xFFFFFFFFL;
							return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
						} catch (Exception e) {
							// Couldn't read memory, return the load address itself as fallback
							return loadAddr;
						}
					}
				}
			}

			// Handle INDIRECT operations (used in SSA form for values that come from multiple paths)
			if (opcode == PcodeOp.INDIRECT) {
				// INDIRECT inputs: [0] = the value, [1] = the PcodeOp that affects it
				if (def.getNumInputs() > 0) {
					return resolveVarnodeToAddress(def.getInput(0), depth + 1);
				}
			}

			// Handle MULTIEQUAL (PHI node in SSA) - try all inputs until we find a valid address
			if (opcode == PcodeOp.MULTIEQUAL) {
				for (int i = 0; i < def.getNumInputs(); i++) {
					Address addr = resolveVarnodeToAddress(def.getInput(i), depth + 1);
					if (addr != null && addr.getOffset() >= 0x1000) {
						return addr;
					}
				}
				return null;
			}

			// Handle operations with single input that pass through values
			switch (opcode) {
				case PcodeOp.COPY:
				case PcodeOp.CAST:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					// These operations pass through values, recurse on input
					if (def.getNumInputs() > 0) {
						return resolveVarnodeToAddress(def.getInput(0), depth + 1);
					}
					break;
			}

			// For other operations with multiple inputs, try input[1] first
			// (input[0] is typically the address space ID for LOAD/STORE operations)
			if (def.getNumInputs() > 1) {
				return resolveVarnodeToAddress(def.getInput(1), depth + 1);
			}

			// Single input operations we haven't handled
			if (def.getNumInputs() > 0) {
				return resolveVarnodeToAddress(def.getInput(0), depth + 1);
			}
		}

		// Couldn't resolve - return null
		return null;
	}

	private Address resolveVarnodeToAddress(Varnode vn) {
		return resolveVarnodeToAddress(vn, 0);
	}

	/**
	 * Attempts to extract an address value from a varnode, validating it's a real memory address.
	 * Returns null if the address appears to be a struct offset or other invalid value.
	 */
	private Address getValidAddress(Varnode vn) {
		Address addr = resolveVarnodeToAddress(vn);
		if (addr == null) {
			return null;
		}

		// If the address is suspiciously small (< 0x1000), it's likely a struct offset, not a real address
		if (addr.getOffset() < 0x1000) {
			return null;
		}

		return addr;
	}

	private void extractArgInfo(
		final FunctionManager funcManager,
		final DecompInterface decompiler,
		final Reference ref) {
		final Address callAddr = ref.getFromAddress();

		// Get the function containing this call
		Function callingFunc = funcManager.getFunctionContaining(callAddr);
		if (callingFunc == null) {
			println("WARNING: Could not find function containing call at " + callAddr);
			return;
		}

		// Decompile the calling function
		DecompileResults decompResults = decompiler.decompileFunction(callingFunc, 30, monitor);
		if (!decompResults.decompileCompleted()) {
			println("WARNING: Decompilation failed for function at " + callingFunc.getEntryPoint());
			return;
		}

		HighFunction highFunc = decompResults.getHighFunction();
		if (highFunc == null) {
			println("WARNING: No high function available at " + callAddr);
			return;
		}

		// Find the PcodeOp at this call address
		Iterator<PcodeOpAST> pcodeOps = highFunc.getPcodeOps(callAddr);
		while (pcodeOps.hasNext()) {
			PcodeOpAST pcodeOp = pcodeOps.next();

			// Check if this is a CALL operation
			if (pcodeOp.getOpcode() == PcodeOp.CALL) {
				println("Call at " + callAddr + ":");
				println("  Function: " + callingFunc.getName());

				// Get all input parameters (index 0 is the call target, so start at 1)
				int numArgs = pcodeOp.getNumInputs() - 1;

				final Varnode dtc_num_node = pcodeOp.getInput(5);
				if (! dtc_num_node.isConstant()) {
					println("  ERROR: DTC number is not a constant");
					return;
				}
				final long dtc_num = dtc_num_node.getOffset();

				final Varnode dtc_type_node = pcodeOp.getInput(6);
				if (! dtc_type_node.isConstant()) {
					println("  ERROR: DTC type is not a constant");
					return;
				}
				final long dtc_type = dtc_type_node.getOffset();

				char dtcPrefix;
				switch ((int)dtc_type) {
					case 0: dtcPrefix = 'P'; break;
					case 1: dtcPrefix = 'C'; break;
					case 2: dtcPrefix = 'B'; break;
					case 3: dtcPrefix = 'U'; break;
					default: dtcPrefix = '?'; break;
				}

				String dtcCode = String.format("%c%04X", dtcPrefix, dtc_num);
				String dtcCALName = String.format("CAL_obd_ii_%c%04X", dtcPrefix, dtc_num);
				String dtcLEAName = String.format("LEA_obd_ii_%c%04X", dtcPrefix, dtc_num);

				final Varnode config_node = pcodeOp.getInput(1);
				final Varnode dtc_state_node = pcodeOp.getInput(2);
				final Varnode fail_counter_node = pcodeOp.getInput(3);
				final Varnode pass_counter_node = pcodeOp.getInput(4);

				Address configAddr = resolveVarnodeToAddress(config_node);
				Address dtcStateAddr = resolveVarnodeToAddress(dtc_state_node);
				Address failCounterAddr = resolveVarnodeToAddress(fail_counter_node);
				Address passCounterAddr = resolveVarnodeToAddress(pass_counter_node);

				if (configAddr != null) {
					println("  Config address: " + configAddr);

					// Add label for config
					try {
						createLabel(configAddr, dtcCALName, true);
						println("    Added label: " + dtcCALName);
					} catch (Exception e) {
						println("    WARNING: Could not add label " + dtcCALName + ": " + e.getMessage());
					}

					// Set data type to u8_obd2level
					try {
						DataTypeManager dtm = currentProgram.getDataTypeManager();
						DataType u8Type = dtm.getDataType("/ECU/u8_obd2level_t6");
						if (u8Type != null) {
							// Clear existing data for the entire range
							int typeSize = u8Type.getLength();
							clearListing(configAddr, configAddr.add(typeSize - 1));
							createData(configAddr, u8Type);
							println("    Set type: u8_obd2level");
						} else {
							println("    WARNING: Data type 'u8_obd2level' not found");
						}
					} catch (Exception e) {
						println("    WARNING: Could not set type: " + e.getMessage());
					}
				} else {
					println("  WARNING: Could not resolve config_node to memory address");
					println("    Varnode: " + config_node);
					if (config_node.getDef() != null) {
						println("    Def opcode: " + config_node.getDef().getMnemonic());
						// Print the inputs to help debug
						PcodeOp def = config_node.getDef();
						for (int i = 0; i < def.getNumInputs(); i++) {
							println("      Input[" + i + "]: " + def.getInput(i));
						}
					}
				}

				// Label the dtc_state address
				if (dtcStateAddr != null) {
					println("  DTC State address: " + dtcStateAddr);
					String dtcStateName = dtcLEAName + "_dtc_state";

					try {
						createLabel(dtcStateAddr, dtcStateName, true);
						println("    Added label: " + dtcStateName);
					} catch (Exception e) {
						println("    WARNING: Could not add label " + dtcStateName + ": " + e.getMessage());
					}

					try {
						DataTypeManager dtm = currentProgram.getDataTypeManager();
						DataType byteType = dtm.getDataType("/byte");
						if (byteType != null) {
							clearListing(dtcStateAddr);
							createData(dtcStateAddr, byteType);
							println("    Set type: byte");
						}
					} catch (Exception e) {
						println("    WARNING: Could not set type: " + e.getMessage());
					}
				} else {
					println("  WARNING: Could not resolve dtc_state_node to memory address");
					println("    Varnode: " + dtc_state_node);
					if (dtc_state_node.getDef() != null) {
						println("    Def opcode: " + dtc_state_node.getDef().getMnemonic());
						// Print the inputs to help debug
						PcodeOp def = dtc_state_node.getDef();
						for (int i = 0; i < def.getNumInputs(); i++) {
							println("      Input[" + i + "]: " + def.getInput(i));
						}
					}
				}

				// Label the fail_counter address
				if (failCounterAddr != null) {
					println("  Fail Counter address: " + failCounterAddr);
					String failCounterName = dtcLEAName + "_fail_counter";

					try {
						createLabel(failCounterAddr, failCounterName, true);
						println("    Added label: " + failCounterName);
					} catch (Exception e) {
						println("    WARNING: Could not add label " + failCounterName + ": " + e.getMessage());
					}

					try {
						DataTypeManager dtm = currentProgram.getDataTypeManager();
						DataType byteType = dtm.getDataType("/byte");
						if (byteType != null) {
							clearListing(failCounterAddr);
							createData(failCounterAddr, byteType);
							println("    Set type: byte");
						}
					} catch (Exception e) {
						println("    WARNING: Could not set type: " + e.getMessage());
					}
				} else {
					println("  WARNING: Could not resolve fail_counter_node to memory address");
					println("    Varnode: " + fail_counter_node);
					if (fail_counter_node.getDef() != null) {
						println("    Def opcode: " + fail_counter_node.getDef().getMnemonic());
						// Print the inputs to help debug
						PcodeOp def = fail_counter_node.getDef();
						for (int i = 0; i < def.getNumInputs(); i++) {
							println("      Input[" + i + "]: " + def.getInput(i));
						}
					}
				}

				// Label the pass_counter address
				if (passCounterAddr != null) {
					println("  Pass Counter address: " + passCounterAddr);
					String passCounterName = dtcLEAName + "_pass_counter";

					try {
						createLabel(passCounterAddr, passCounterName, true);
						println("    Added label: " + passCounterName);
					} catch (Exception e) {
						println("    WARNING: Could not add label " + passCounterName + ": " + e.getMessage());
					}

					try {
						DataTypeManager dtm = currentProgram.getDataTypeManager();
						DataType byteType = dtm.getDataType("/byte");
						if (byteType != null) {
							clearListing(passCounterAddr);
							createData(passCounterAddr, byteType);
							println("    Set type: byte");
						}
					} catch (Exception e) {
						println("    WARNING: Could not set type: " + e.getMessage());
					}
				} else {
					println("  WARNING: Could not resolve pass_counter_node to memory address");
					println("    Varnode: " + pass_counter_node);
					if (pass_counter_node.getDef() != null) {
						println("    Def opcode: " + pass_counter_node.getDef().getMnemonic());
						// Print the inputs to help debug
						PcodeOp def = pass_counter_node.getDef();
						for (int i = 0; i < def.getNumInputs(); i++) {
							println("      Input[" + i + "]: " + def.getInput(i));
						}
					}
				}

				println("");
			}
		}
	}

	@Override
	public void run() throws Exception {
		println("OBD-II Code Configuration Analysis");
		println("===================================\n");

		final FunctionManager funcManager = currentProgram.getFunctionManager();
		Function targetFunc = null;
		for (final Function func : funcManager.getFunctions(true)) {
			if (func.getName().equals(OBD_II_FAIL_FUNNAME)) {
				targetFunc = func;
				break;
			}
		}
		if (targetFunc == null) {
			println("ERROR: Function 'obd_ii_monitor_fail_transition' not found!");
			return;
		}

		println("Found function: " + targetFunc.getName() + " at " + targetFunc.getEntryPoint());
		println("\nSearching for all calls to this function...\n");

		// Initialize the decompiler
		final DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		// Get all references to this function
		final ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(targetFunc.getEntryPoint());

		int processedCount = 0;
		final int MAX_TO_PROCESS = Integer.MAX_VALUE;

		while (refIter.hasNext() && processedCount < MAX_TO_PROCESS) {
			final Reference ref = refIter.next();
			extractArgInfo(funcManager, decompiler, ref);
			processedCount++;
		}

		println("\n=================================");
		println("Processed " + processedCount + " calls (limited to " + MAX_TO_PROCESS + " for diagnostics)");
		println("=================================");

		// Cleanup
		decompiler.dispose();
	}
}
