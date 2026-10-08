//MC68336/68376 Register Memory Map Script
//Creates labels for all on-chip module registers from Appendix D of the MC68336/376 User's Manual
//(modules mapped at $FFF000, i.e. SIMCR MM bit = 1, as used by the Lotus T4 firmware)
//All registers are prefixed with REG_ for easy identification
//@author Generated from MC68336376UM.pdf
//@category MC68332
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class MC68376_RegisterMap extends GhidraScript {

	private DataTypeManager dtm;
	private SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();
		symbolTable = currentProgram.getSymbolTable();

		println("MC68336/68376 Register Memory Map Script");
		println("=========================================");

		// Create TouCAN registers with all message buffers
		createTouCANRegisters();

		// Create QADC registers
		createQADCRegisters();

		// Create CTM4 registers
		createCTM4Registers();

		// Create MRM registers
		createMRMRegisters();

		// Create SIM registers
		createSIMRegisters();

		// Create TPURAM registers
		createTPURAMRegisters();

		// Create SRAM registers
		createSRAMRegisters();

		// Create QSM registers
		createQSMRegisters();

		// Create TPU registers
		createTPURegisters();

		// Create TPU parameter RAM registers
		createTPUParameterRAM();

		println("Register mapping complete!");
	}

	private void createRegLabel(long address, String name, int size) throws Exception {
		Address addr = toAddr(address);
		String regName = "REG_" + name;

		// Remove any existing labels at this address
		Symbol[] existingSymbols = symbolTable.getSymbols(addr);
		for (Symbol sym : existingSymbols) {
			if (!sym.isPrimary() || sym.getSource() != SourceType.DEFAULT) {
				sym.delete();
			}
		}

		// Create the new label with REG_ prefix
		createLabel(addr, regName, true);

		// Apply appropriate data type based on size (word registers on CPU32 are 16-bit)
		String typeName = null;
		switch (size) {
			case 1: typeName = "/byte"; break;
			case 2: typeName = "/ushort"; break;
			case 4: typeName = "/uint"; break;
		}

		if (typeName != null) {
			DataType dt = dtm.getDataType(typeName);
			if (dt != null) {
				clearListing(addr, addr.add(size - 1));
				createData(addr, dt);
			}
		}
	}

	private void createTouCANRegisters() throws Exception {
		println("Creating TouCAN (CAN 2.0B controller) registers...");
		createRegLabel(0xFFF080L, "CANMCR", 2);
		createRegLabel(0xFFF082L, "CANTCR", 2);
		createRegLabel(0xFFF084L, "CANICR", 2);
		createRegLabel(0xFFF086L, "CANCTRL0", 1);
		createRegLabel(0xFFF087L, "CANCTRL1", 1);
		createRegLabel(0xFFF088L, "PRESDIV", 1);
		createRegLabel(0xFFF089L, "CANCTRL2", 1);
		createRegLabel(0xFFF08AL, "TIMER", 2);
		createRegLabel(0xFFF090L, "RXGMSKHI", 2);
		createRegLabel(0xFFF092L, "RXGMSKLO", 2);
		createRegLabel(0xFFF094L, "RX14MSKHI", 2);
		createRegLabel(0xFFF096L, "RX14MSKLO", 2);
		createRegLabel(0xFFF098L, "RX15MSKHI", 2);
		createRegLabel(0xFFF09AL, "RX15MSKLO", 2);
		createRegLabel(0xFFF0A0L, "ESTAT", 2);
		createRegLabel(0xFFF0A2L, "IMASK", 2);
		createRegLabel(0xFFF0A4L, "IFLAG", 2);
		createRegLabel(0xFFF0A6L, "RXECTR", 1);
		createRegLabel(0xFFF0A7L, "TXECTR", 1);
		createRegLabel(0xFFF100L, "MB0CS", 2);
		createRegLabel(0xFFF102L, "MB0IDHI", 2);
		createRegLabel(0xFFF104L, "MB0IDLO", 2);
		createRegLabel(0xFFF106L, "MB0D0", 2);
		createRegLabel(0xFFF108L, "MB0D1", 2);
		createRegLabel(0xFFF10AL, "MB0D2", 2);
		createRegLabel(0xFFF10CL, "MB0D3", 2);
		createRegLabel(0xFFF110L, "MB1CS", 2);
		createRegLabel(0xFFF112L, "MB1IDHI", 2);
		createRegLabel(0xFFF114L, "MB1IDLO", 2);
		createRegLabel(0xFFF116L, "MB1D0", 2);
		createRegLabel(0xFFF118L, "MB1D1", 2);
		createRegLabel(0xFFF11AL, "MB1D2", 2);
		createRegLabel(0xFFF11CL, "MB1D3", 2);
		createRegLabel(0xFFF120L, "MB2CS", 2);
		createRegLabel(0xFFF122L, "MB2IDHI", 2);
		createRegLabel(0xFFF124L, "MB2IDLO", 2);
		createRegLabel(0xFFF126L, "MB2D0", 2);
		createRegLabel(0xFFF128L, "MB2D1", 2);
		createRegLabel(0xFFF12AL, "MB2D2", 2);
		createRegLabel(0xFFF12CL, "MB2D3", 2);
		createRegLabel(0xFFF130L, "MB3CS", 2);
		createRegLabel(0xFFF132L, "MB3IDHI", 2);
		createRegLabel(0xFFF134L, "MB3IDLO", 2);
		createRegLabel(0xFFF136L, "MB3D0", 2);
		createRegLabel(0xFFF138L, "MB3D1", 2);
		createRegLabel(0xFFF13AL, "MB3D2", 2);
		createRegLabel(0xFFF13CL, "MB3D3", 2);
		createRegLabel(0xFFF140L, "MB4CS", 2);
		createRegLabel(0xFFF142L, "MB4IDHI", 2);
		createRegLabel(0xFFF144L, "MB4IDLO", 2);
		createRegLabel(0xFFF146L, "MB4D0", 2);
		createRegLabel(0xFFF148L, "MB4D1", 2);
		createRegLabel(0xFFF14AL, "MB4D2", 2);
		createRegLabel(0xFFF14CL, "MB4D3", 2);
		createRegLabel(0xFFF150L, "MB5CS", 2);
		createRegLabel(0xFFF152L, "MB5IDHI", 2);
		createRegLabel(0xFFF154L, "MB5IDLO", 2);
		createRegLabel(0xFFF156L, "MB5D0", 2);
		createRegLabel(0xFFF158L, "MB5D1", 2);
		createRegLabel(0xFFF15AL, "MB5D2", 2);
		createRegLabel(0xFFF15CL, "MB5D3", 2);
		createRegLabel(0xFFF160L, "MB6CS", 2);
		createRegLabel(0xFFF162L, "MB6IDHI", 2);
		createRegLabel(0xFFF164L, "MB6IDLO", 2);
		createRegLabel(0xFFF166L, "MB6D0", 2);
		createRegLabel(0xFFF168L, "MB6D1", 2);
		createRegLabel(0xFFF16AL, "MB6D2", 2);
		createRegLabel(0xFFF16CL, "MB6D3", 2);
		createRegLabel(0xFFF170L, "MB7CS", 2);
		createRegLabel(0xFFF172L, "MB7IDHI", 2);
		createRegLabel(0xFFF174L, "MB7IDLO", 2);
		createRegLabel(0xFFF176L, "MB7D0", 2);
		createRegLabel(0xFFF178L, "MB7D1", 2);
		createRegLabel(0xFFF17AL, "MB7D2", 2);
		createRegLabel(0xFFF17CL, "MB7D3", 2);
		createRegLabel(0xFFF180L, "MB8CS", 2);
		createRegLabel(0xFFF182L, "MB8IDHI", 2);
		createRegLabel(0xFFF184L, "MB8IDLO", 2);
		createRegLabel(0xFFF186L, "MB8D0", 2);
		createRegLabel(0xFFF188L, "MB8D1", 2);
		createRegLabel(0xFFF18AL, "MB8D2", 2);
		createRegLabel(0xFFF18CL, "MB8D3", 2);
		createRegLabel(0xFFF190L, "MB9CS", 2);
		createRegLabel(0xFFF192L, "MB9IDHI", 2);
		createRegLabel(0xFFF194L, "MB9IDLO", 2);
		createRegLabel(0xFFF196L, "MB9D0", 2);
		createRegLabel(0xFFF198L, "MB9D1", 2);
		createRegLabel(0xFFF19AL, "MB9D2", 2);
		createRegLabel(0xFFF19CL, "MB9D3", 2);
		createRegLabel(0xFFF1A0L, "MB10CS", 2);
		createRegLabel(0xFFF1A2L, "MB10IDHI", 2);
		createRegLabel(0xFFF1A4L, "MB10IDLO", 2);
		createRegLabel(0xFFF1A6L, "MB10D0", 2);
		createRegLabel(0xFFF1A8L, "MB10D1", 2);
		createRegLabel(0xFFF1AAL, "MB10D2", 2);
		createRegLabel(0xFFF1ACL, "MB10D3", 2);
		createRegLabel(0xFFF1B0L, "MB11CS", 2);
		createRegLabel(0xFFF1B2L, "MB11IDHI", 2);
		createRegLabel(0xFFF1B4L, "MB11IDLO", 2);
		createRegLabel(0xFFF1B6L, "MB11D0", 2);
		createRegLabel(0xFFF1B8L, "MB11D1", 2);
		createRegLabel(0xFFF1BAL, "MB11D2", 2);
		createRegLabel(0xFFF1BCL, "MB11D3", 2);
		createRegLabel(0xFFF1C0L, "MB12CS", 2);
		createRegLabel(0xFFF1C2L, "MB12IDHI", 2);
		createRegLabel(0xFFF1C4L, "MB12IDLO", 2);
		createRegLabel(0xFFF1C6L, "MB12D0", 2);
		createRegLabel(0xFFF1C8L, "MB12D1", 2);
		createRegLabel(0xFFF1CAL, "MB12D2", 2);
		createRegLabel(0xFFF1CCL, "MB12D3", 2);
		createRegLabel(0xFFF1D0L, "MB13CS", 2);
		createRegLabel(0xFFF1D2L, "MB13IDHI", 2);
		createRegLabel(0xFFF1D4L, "MB13IDLO", 2);
		createRegLabel(0xFFF1D6L, "MB13D0", 2);
		createRegLabel(0xFFF1D8L, "MB13D1", 2);
		createRegLabel(0xFFF1DAL, "MB13D2", 2);
		createRegLabel(0xFFF1DCL, "MB13D3", 2);
		createRegLabel(0xFFF1E0L, "MB14CS", 2);
		createRegLabel(0xFFF1E2L, "MB14IDHI", 2);
		createRegLabel(0xFFF1E4L, "MB14IDLO", 2);
		createRegLabel(0xFFF1E6L, "MB14D0", 2);
		createRegLabel(0xFFF1E8L, "MB14D1", 2);
		createRegLabel(0xFFF1EAL, "MB14D2", 2);
		createRegLabel(0xFFF1ECL, "MB14D3", 2);
		createRegLabel(0xFFF1F0L, "MB15CS", 2);
		createRegLabel(0xFFF1F2L, "MB15IDHI", 2);
		createRegLabel(0xFFF1F4L, "MB15IDLO", 2);
		createRegLabel(0xFFF1F6L, "MB15D0", 2);
		createRegLabel(0xFFF1F8L, "MB15D1", 2);
		createRegLabel(0xFFF1FAL, "MB15D2", 2);
		createRegLabel(0xFFF1FCL, "MB15D3", 2);
	}
	private void createQADCRegisters() throws Exception {
		println("Creating QADC (Queued ADC) registers...");
		createRegLabel(0xFFF200L, "QADCMCR", 2);
		createRegLabel(0xFFF202L, "QADCTEST", 2);
		createRegLabel(0xFFF204L, "QADCINT", 2);
		createRegLabel(0xFFF206L, "PORTQA", 1);
		createRegLabel(0xFFF207L, "PORTQB", 1);
		createRegLabel(0xFFF208L, "DDRQA", 2);
		createRegLabel(0xFFF20AL, "QACR0", 2);
		createRegLabel(0xFFF20CL, "QACR1", 2);
		createRegLabel(0xFFF20EL, "QACR2", 2);
		createRegLabel(0xFFF210L, "QASR", 2);
		createRegLabel(0xFFF230L, "CCW0", 2);
		createRegLabel(0xFFF232L, "CCW1", 2);
		createRegLabel(0xFFF234L, "CCW2", 2);
		createRegLabel(0xFFF236L, "CCW3", 2);
		createRegLabel(0xFFF238L, "CCW4", 2);
		createRegLabel(0xFFF23AL, "CCW5", 2);
		createRegLabel(0xFFF23CL, "CCW6", 2);
		createRegLabel(0xFFF23EL, "CCW7", 2);
		createRegLabel(0xFFF240L, "CCW8", 2);
		createRegLabel(0xFFF242L, "CCW9", 2);
		createRegLabel(0xFFF244L, "CCW10", 2);
		createRegLabel(0xFFF246L, "CCW11", 2);
		createRegLabel(0xFFF248L, "CCW12", 2);
		createRegLabel(0xFFF24AL, "CCW13", 2);
		createRegLabel(0xFFF24CL, "CCW14", 2);
		createRegLabel(0xFFF24EL, "CCW15", 2);
		createRegLabel(0xFFF250L, "CCW16", 2);
		createRegLabel(0xFFF252L, "CCW17", 2);
		createRegLabel(0xFFF254L, "CCW18", 2);
		createRegLabel(0xFFF256L, "CCW19", 2);
		createRegLabel(0xFFF258L, "CCW20", 2);
		createRegLabel(0xFFF25AL, "CCW21", 2);
		createRegLabel(0xFFF25CL, "CCW22", 2);
		createRegLabel(0xFFF25EL, "CCW23", 2);
		createRegLabel(0xFFF260L, "CCW24", 2);
		createRegLabel(0xFFF262L, "CCW25", 2);
		createRegLabel(0xFFF264L, "CCW26", 2);
		createRegLabel(0xFFF266L, "CCW27", 2);
		createRegLabel(0xFFF268L, "CCW28", 2);
		createRegLabel(0xFFF26AL, "CCW29", 2);
		createRegLabel(0xFFF26CL, "CCW30", 2);
		createRegLabel(0xFFF26EL, "CCW31", 2);
		createRegLabel(0xFFF2B0L, "RJURR0", 2);
		createRegLabel(0xFFF2B2L, "RJURR1", 2);
		createRegLabel(0xFFF2B4L, "RJURR2", 2);
		createRegLabel(0xFFF2B6L, "RJURR3", 2);
		createRegLabel(0xFFF2B8L, "RJURR4", 2);
		createRegLabel(0xFFF2BAL, "RJURR5", 2);
		createRegLabel(0xFFF2BCL, "RJURR6", 2);
		createRegLabel(0xFFF2BEL, "RJURR7", 2);
		createRegLabel(0xFFF2C0L, "RJURR8", 2);
		createRegLabel(0xFFF2C2L, "RJURR9", 2);
		createRegLabel(0xFFF2C4L, "RJURR10", 2);
		createRegLabel(0xFFF2C6L, "RJURR11", 2);
		createRegLabel(0xFFF2C8L, "RJURR12", 2);
		createRegLabel(0xFFF2CAL, "RJURR13", 2);
		createRegLabel(0xFFF2CCL, "RJURR14", 2);
		createRegLabel(0xFFF2CEL, "RJURR15", 2);
		createRegLabel(0xFFF2D0L, "RJURR16", 2);
		createRegLabel(0xFFF2D2L, "RJURR17", 2);
		createRegLabel(0xFFF2D4L, "RJURR18", 2);
		createRegLabel(0xFFF2D6L, "RJURR19", 2);
		createRegLabel(0xFFF2D8L, "RJURR20", 2);
		createRegLabel(0xFFF2DAL, "RJURR21", 2);
		createRegLabel(0xFFF2DCL, "RJURR22", 2);
		createRegLabel(0xFFF2DEL, "RJURR23", 2);
		createRegLabel(0xFFF2E0L, "RJURR24", 2);
		createRegLabel(0xFFF2E2L, "RJURR25", 2);
		createRegLabel(0xFFF2E4L, "RJURR26", 2);
		createRegLabel(0xFFF2E6L, "RJURR27", 2);
		createRegLabel(0xFFF2E8L, "RJURR28", 2);
		createRegLabel(0xFFF2EAL, "RJURR29", 2);
		createRegLabel(0xFFF2ECL, "RJURR30", 2);
		createRegLabel(0xFFF2EEL, "RJURR31", 2);
		createRegLabel(0xFFF330L, "LJSRR0", 2);
		createRegLabel(0xFFF332L, "LJSRR1", 2);
		createRegLabel(0xFFF334L, "LJSRR2", 2);
		createRegLabel(0xFFF336L, "LJSRR3", 2);
		createRegLabel(0xFFF338L, "LJSRR4", 2);
		createRegLabel(0xFFF33AL, "LJSRR5", 2);
		createRegLabel(0xFFF33CL, "LJSRR6", 2);
		createRegLabel(0xFFF33EL, "LJSRR7", 2);
		createRegLabel(0xFFF340L, "LJSRR8", 2);
		createRegLabel(0xFFF342L, "LJSRR9", 2);
		createRegLabel(0xFFF344L, "LJSRR10", 2);
		createRegLabel(0xFFF346L, "LJSRR11", 2);
		createRegLabel(0xFFF348L, "LJSRR12", 2);
		createRegLabel(0xFFF34AL, "LJSRR13", 2);
		createRegLabel(0xFFF34CL, "LJSRR14", 2);
		createRegLabel(0xFFF34EL, "LJSRR15", 2);
		createRegLabel(0xFFF350L, "LJSRR16", 2);
		createRegLabel(0xFFF352L, "LJSRR17", 2);
		createRegLabel(0xFFF354L, "LJSRR18", 2);
		createRegLabel(0xFFF356L, "LJSRR19", 2);
		createRegLabel(0xFFF358L, "LJSRR20", 2);
		createRegLabel(0xFFF35AL, "LJSRR21", 2);
		createRegLabel(0xFFF35CL, "LJSRR22", 2);
		createRegLabel(0xFFF35EL, "LJSRR23", 2);
		createRegLabel(0xFFF360L, "LJSRR24", 2);
		createRegLabel(0xFFF362L, "LJSRR25", 2);
		createRegLabel(0xFFF364L, "LJSRR26", 2);
		createRegLabel(0xFFF366L, "LJSRR27", 2);
		createRegLabel(0xFFF368L, "LJSRR28", 2);
		createRegLabel(0xFFF36AL, "LJSRR29", 2);
		createRegLabel(0xFFF36CL, "LJSRR30", 2);
		createRegLabel(0xFFF36EL, "LJSRR31", 2);
		createRegLabel(0xFFF3B0L, "LJURR0", 2);
		createRegLabel(0xFFF3B2L, "LJURR1", 2);
		createRegLabel(0xFFF3B4L, "LJURR2", 2);
		createRegLabel(0xFFF3B6L, "LJURR3", 2);
		createRegLabel(0xFFF3B8L, "LJURR4", 2);
		createRegLabel(0xFFF3BAL, "LJURR5", 2);
		createRegLabel(0xFFF3BCL, "LJURR6", 2);
		createRegLabel(0xFFF3BEL, "LJURR7", 2);
		createRegLabel(0xFFF3C0L, "LJURR8", 2);
		createRegLabel(0xFFF3C2L, "LJURR9", 2);
		createRegLabel(0xFFF3C4L, "LJURR10", 2);
		createRegLabel(0xFFF3C6L, "LJURR11", 2);
		createRegLabel(0xFFF3C8L, "LJURR12", 2);
		createRegLabel(0xFFF3CAL, "LJURR13", 2);
		createRegLabel(0xFFF3CCL, "LJURR14", 2);
		createRegLabel(0xFFF3CEL, "LJURR15", 2);
		createRegLabel(0xFFF3D0L, "LJURR16", 2);
		createRegLabel(0xFFF3D2L, "LJURR17", 2);
		createRegLabel(0xFFF3D4L, "LJURR18", 2);
		createRegLabel(0xFFF3D6L, "LJURR19", 2);
		createRegLabel(0xFFF3D8L, "LJURR20", 2);
		createRegLabel(0xFFF3DAL, "LJURR21", 2);
		createRegLabel(0xFFF3DCL, "LJURR22", 2);
		createRegLabel(0xFFF3DEL, "LJURR23", 2);
		createRegLabel(0xFFF3E0L, "LJURR24", 2);
		createRegLabel(0xFFF3E2L, "LJURR25", 2);
		createRegLabel(0xFFF3E4L, "LJURR26", 2);
		createRegLabel(0xFFF3E6L, "LJURR27", 2);
		createRegLabel(0xFFF3E8L, "LJURR28", 2);
		createRegLabel(0xFFF3EAL, "LJURR29", 2);
		createRegLabel(0xFFF3ECL, "LJURR30", 2);
		createRegLabel(0xFFF3EEL, "LJURR31", 2);
	}
	private void createCTM4Registers() throws Exception {
		println("Creating CTM4 (Configurable Timer Module) registers...");
		createRegLabel(0xFFF400L, "BIUMCR", 2);
		createRegLabel(0xFFF402L, "BIUTEST", 2);
		createRegLabel(0xFFF404L, "BIUTBR", 2);
		createRegLabel(0xFFF408L, "CPCR", 2);
		createRegLabel(0xFFF40AL, "CPTR", 2);
		createRegLabel(0xFFF410L, "MCSM2SIC", 2);
		createRegLabel(0xFFF412L, "MCSM2CNT", 2);
		createRegLabel(0xFFF414L, "MCSM2ML", 2);
		createRegLabel(0xFFF418L, "DASM3SIC", 2);
		createRegLabel(0xFFF41AL, "DASM3A", 2);
		createRegLabel(0xFFF41CL, "DASM3B", 2);
		createRegLabel(0xFFF420L, "DASM4SIC", 2);
		createRegLabel(0xFFF422L, "DASM4A", 2);
		createRegLabel(0xFFF424L, "DASM4B", 2);
		createRegLabel(0xFFF428L, "PWM5SIC", 2);
		createRegLabel(0xFFF42AL, "PWM5A", 2);
		createRegLabel(0xFFF42CL, "PWM5B", 2);
		createRegLabel(0xFFF42EL, "PWM5C", 2);
		createRegLabel(0xFFF430L, "PWM6SIC", 2);
		createRegLabel(0xFFF432L, "PWM6A", 2);
		createRegLabel(0xFFF434L, "PWM6B", 2);
		createRegLabel(0xFFF436L, "PWM6C", 2);
		createRegLabel(0xFFF438L, "PWM7SIC", 2);
		createRegLabel(0xFFF43AL, "PWM7A", 2);
		createRegLabel(0xFFF43CL, "PWM7B", 2);
		createRegLabel(0xFFF43EL, "PWM7C", 2);
		createRegLabel(0xFFF440L, "PWM8SIC", 2);
		createRegLabel(0xFFF442L, "PWM8A", 2);
		createRegLabel(0xFFF444L, "PWM8B", 2);
		createRegLabel(0xFFF446L, "PWM8C", 2);
		createRegLabel(0xFFF448L, "DASM9SIC", 2);
		createRegLabel(0xFFF44AL, "DASM9A", 2);
		createRegLabel(0xFFF44CL, "DASM9B", 2);
		createRegLabel(0xFFF450L, "DASM10SIC", 2);
		createRegLabel(0xFFF452L, "DASM10A", 2);
		createRegLabel(0xFFF454L, "DASM10B", 2);
		createRegLabel(0xFFF458L, "MCSM11SIC", 2);
		createRegLabel(0xFFF45AL, "MCSM11CNT", 2);
		createRegLabel(0xFFF45CL, "MCSM11ML", 2);
		createRegLabel(0xFFF460L, "FCSM12SIC", 2);
		createRegLabel(0xFFF462L, "FCSM12CNT", 2);
	}
	private void createMRMRegisters() throws Exception {
		println("Creating MRM (Masked ROM Module) registers...");
		createRegLabel(0xFFF820L, "MRMCR", 2);
		createRegLabel(0xFFF824L, "ROMBAH", 2);
		createRegLabel(0xFFF826L, "ROMBAL", 2);
		createRegLabel(0xFFF828L, "SIGHI", 2);
		createRegLabel(0xFFF82AL, "SIGLO", 2);
		createRegLabel(0xFFF830L, "ROMBS0", 2);
		createRegLabel(0xFFF832L, "ROMBS1", 2);
		createRegLabel(0xFFF834L, "ROMBS2", 2);
		createRegLabel(0xFFF836L, "ROMBS3", 2);
	}
	private void createSIMRegisters() throws Exception {
		println("Creating SIM (System Integration Module) registers...");
		createRegLabel(0xFFFA00L, "SIMCR", 2);
		createRegLabel(0xFFFA02L, "SIMTR", 2);
		createRegLabel(0xFFFA04L, "SYNCR", 2);
		createRegLabel(0xFFFA07L, "RSR", 1);
		createRegLabel(0xFFFA08L, "SIMTRE", 2);
		createRegLabel(0xFFFA11L, "PORTE0", 1);
		createRegLabel(0xFFFA13L, "PORTE1", 1);
		createRegLabel(0xFFFA15L, "DDRE", 1);
		createRegLabel(0xFFFA17L, "PEPAR", 1);
		createRegLabel(0xFFFA19L, "PORTF0", 1);
		createRegLabel(0xFFFA1BL, "PORTF1", 1);
		createRegLabel(0xFFFA1DL, "DDRF", 1);
		createRegLabel(0xFFFA1FL, "PFPAR", 1);
		createRegLabel(0xFFFA21L, "SYPCR", 2);
		createRegLabel(0xFFFA22L, "PICR", 2);
		createRegLabel(0xFFFA24L, "PITR", 2);
		createRegLabel(0xFFFA27L, "SWSR", 1);
		createRegLabel(0xFFFA30L, "TSTMSRA", 2);
		createRegLabel(0xFFFA32L, "TSTMSRB", 2);
		createRegLabel(0xFFFA34L, "TSTSC", 2);
		createRegLabel(0xFFFA36L, "TSTRC", 2);
		createRegLabel(0xFFFA38L, "CREG", 2);
		createRegLabel(0xFFFA3AL, "DREG", 2);
		createRegLabel(0xFFFA41L, "PORTC", 1);
		createRegLabel(0xFFFA44L, "CSPAR0", 2);
		createRegLabel(0xFFFA46L, "CSPAR1", 2);
		createRegLabel(0xFFFA48L, "CSBARBT", 2);
		createRegLabel(0xFFFA4AL, "CSORBT", 2);
		createRegLabel(0xFFFA4CL, "CSBAR0", 2);
		createRegLabel(0xFFFA4EL, "CSOR0", 2);
		createRegLabel(0xFFFA50L, "CSBAR1", 2);
		createRegLabel(0xFFFA52L, "CSOR1", 2);
		createRegLabel(0xFFFA54L, "CSBAR2", 2);
		createRegLabel(0xFFFA56L, "CSOR2", 2);
		createRegLabel(0xFFFA58L, "CSBAR3", 2);
		createRegLabel(0xFFFA5AL, "CSOR3", 2);
		createRegLabel(0xFFFA5CL, "CSBAR4", 2);
		createRegLabel(0xFFFA5EL, "CSOR4", 2);
		createRegLabel(0xFFFA60L, "CSBAR5", 2);
		createRegLabel(0xFFFA62L, "CSOR5", 2);
		createRegLabel(0xFFFA64L, "CSBAR6", 2);
		createRegLabel(0xFFFA66L, "CSOR6", 2);
		createRegLabel(0xFFFA68L, "CSBAR7", 2);
		createRegLabel(0xFFFA6AL, "CSOR7", 2);
		createRegLabel(0xFFFA6CL, "CSBAR8", 2);
		createRegLabel(0xFFFA6EL, "CSOR8", 2);
		createRegLabel(0xFFFA70L, "CSBAR9", 2);
		createRegLabel(0xFFFA72L, "CSOR9", 2);
		createRegLabel(0xFFFA74L, "CSBAR10", 2);
		createRegLabel(0xFFFA76L, "CSOR10", 2);
	}
	private void createTPURAMRegisters() throws Exception {
		println("Creating TPURAM (TPU RAM control) registers...");
		createRegLabel(0xFFFB00L, "TRAMMCR", 2);
		createRegLabel(0xFFFB02L, "TRAMTST", 2);
		createRegLabel(0xFFFB04L, "TRAMBAR", 2);
	}
	private void createSRAMRegisters() throws Exception {
		println("Creating SRAM (Standby RAM control) registers...");
		createRegLabel(0xFFFB40L, "RAMMCR", 2);
		createRegLabel(0xFFFB42L, "RAMTST", 2);
		createRegLabel(0xFFFB44L, "RAMBAH", 2);
		createRegLabel(0xFFFB46L, "RAMBAL", 2);
	}
	private void createQSMRegisters() throws Exception {
		println("Creating QSM (Queued Serial Module) registers...");
		createRegLabel(0xFFFC00L, "QSMCR", 2);
		createRegLabel(0xFFFC02L, "QTEST", 2);
		createRegLabel(0xFFFC04L, "QILR", 1);
		createRegLabel(0xFFFC05L, "QIVR", 1);
		createRegLabel(0xFFFC08L, "SCCR0", 2);
		createRegLabel(0xFFFC0AL, "SCCR1", 2);
		createRegLabel(0xFFFC0CL, "SCSR", 2);
		createRegLabel(0xFFFC0EL, "SCDR", 2);
		createRegLabel(0xFFFC15L, "PORTQS", 1);
		createRegLabel(0xFFFC16L, "PQSPAR", 1);
		createRegLabel(0xFFFC17L, "DDRQS", 1);
		createRegLabel(0xFFFC18L, "SPCR0", 2);
		createRegLabel(0xFFFC1AL, "SPCR1", 2);
		createRegLabel(0xFFFC1CL, "SPCR2", 2);
		createRegLabel(0xFFFC1EL, "SPCR3", 1);
		createRegLabel(0xFFFC1FL, "SPSR", 1);
		createRegLabel(0xFFFD00L, "RR0", 2);
		createRegLabel(0xFFFD02L, "RR1", 2);
		createRegLabel(0xFFFD04L, "RR2", 2);
		createRegLabel(0xFFFD06L, "RR3", 2);
		createRegLabel(0xFFFD08L, "RR4", 2);
		createRegLabel(0xFFFD0AL, "RR5", 2);
		createRegLabel(0xFFFD0CL, "RR6", 2);
		createRegLabel(0xFFFD0EL, "RR7", 2);
		createRegLabel(0xFFFD10L, "RR8", 2);
		createRegLabel(0xFFFD12L, "RR9", 2);
		createRegLabel(0xFFFD14L, "RR10", 2);
		createRegLabel(0xFFFD16L, "RR11", 2);
		createRegLabel(0xFFFD18L, "RR12", 2);
		createRegLabel(0xFFFD1AL, "RR13", 2);
		createRegLabel(0xFFFD1CL, "RR14", 2);
		createRegLabel(0xFFFD1EL, "RR15", 2);
		createRegLabel(0xFFFD20L, "TR0", 2);
		createRegLabel(0xFFFD22L, "TR1", 2);
		createRegLabel(0xFFFD24L, "TR2", 2);
		createRegLabel(0xFFFD26L, "TR3", 2);
		createRegLabel(0xFFFD28L, "TR4", 2);
		createRegLabel(0xFFFD2AL, "TR5", 2);
		createRegLabel(0xFFFD2CL, "TR6", 2);
		createRegLabel(0xFFFD2EL, "TR7", 2);
		createRegLabel(0xFFFD30L, "TR8", 2);
		createRegLabel(0xFFFD32L, "TR9", 2);
		createRegLabel(0xFFFD34L, "TR10", 2);
		createRegLabel(0xFFFD36L, "TR11", 2);
		createRegLabel(0xFFFD38L, "TR12", 2);
		createRegLabel(0xFFFD3AL, "TR13", 2);
		createRegLabel(0xFFFD3CL, "TR14", 2);
		createRegLabel(0xFFFD3EL, "TR15", 2);
		createRegLabel(0xFFFD40L, "CR0", 1);
		createRegLabel(0xFFFD41L, "CR1", 1);
		createRegLabel(0xFFFD42L, "CR2", 1);
		createRegLabel(0xFFFD43L, "CR3", 1);
		createRegLabel(0xFFFD44L, "CR4", 1);
		createRegLabel(0xFFFD45L, "CR5", 1);
		createRegLabel(0xFFFD46L, "CR6", 1);
		createRegLabel(0xFFFD47L, "CR7", 1);
		createRegLabel(0xFFFD48L, "CR8", 1);
		createRegLabel(0xFFFD49L, "CR9", 1);
		createRegLabel(0xFFFD4AL, "CR10", 1);
		createRegLabel(0xFFFD4BL, "CR11", 1);
		createRegLabel(0xFFFD4CL, "CR12", 1);
		createRegLabel(0xFFFD4DL, "CR13", 1);
		createRegLabel(0xFFFD4EL, "CR14", 1);
		createRegLabel(0xFFFD4FL, "CR15", 1);
	}
	private void createTPURegisters() throws Exception {
		println("Creating TPU (Time Processor Unit) registers...");
		createRegLabel(0xFFFE00L, "TPUMCR", 2);
		createRegLabel(0xFFFE02L, "TCR", 2);
		createRegLabel(0xFFFE04L, "DSCR", 2);
		createRegLabel(0xFFFE06L, "DSSR", 2);
		createRegLabel(0xFFFE08L, "TICR", 2);
		createRegLabel(0xFFFE0AL, "CIER", 2);
		createRegLabel(0xFFFE0CL, "CFSR0", 2);
		createRegLabel(0xFFFE0EL, "CFSR1", 2);
		createRegLabel(0xFFFE10L, "CFSR2", 2);
		createRegLabel(0xFFFE12L, "CFSR3", 2);
		createRegLabel(0xFFFE14L, "HSQR0", 2);
		createRegLabel(0xFFFE16L, "HSQR1", 2);
		createRegLabel(0xFFFE18L, "HSRR0", 2);
		createRegLabel(0xFFFE1AL, "HSRR1", 2);
		createRegLabel(0xFFFE1CL, "CPR0", 2);
		createRegLabel(0xFFFE1EL, "CPR1", 2);
		createRegLabel(0xFFFE20L, "CISR", 2);
		createRegLabel(0xFFFE22L, "LR", 2);
		createRegLabel(0xFFFE24L, "SGLR", 2);
		createRegLabel(0xFFFE26L, "DCNR", 2);
	}
	private void createTPUParameterRAM() throws Exception {
		println("Creating TPU parameter RAM registers...");
		createRegLabel(0xFFFF00L, "TPU_CH0_P0", 2);
		createRegLabel(0xFFFF02L, "TPU_CH0_P1", 2);
		createRegLabel(0xFFFF04L, "TPU_CH0_P2", 2);
		createRegLabel(0xFFFF06L, "TPU_CH0_P3", 2);
		createRegLabel(0xFFFF08L, "TPU_CH0_P4", 2);
		createRegLabel(0xFFFF0AL, "TPU_CH0_P5", 2);
		createRegLabel(0xFFFF10L, "TPU_CH1_P0", 2);
		createRegLabel(0xFFFF12L, "TPU_CH1_P1", 2);
		createRegLabel(0xFFFF14L, "TPU_CH1_P2", 2);
		createRegLabel(0xFFFF16L, "TPU_CH1_P3", 2);
		createRegLabel(0xFFFF18L, "TPU_CH1_P4", 2);
		createRegLabel(0xFFFF1AL, "TPU_CH1_P5", 2);
		createRegLabel(0xFFFF20L, "TPU_CH2_P0", 2);
		createRegLabel(0xFFFF22L, "TPU_CH2_P1", 2);
		createRegLabel(0xFFFF24L, "TPU_CH2_P2", 2);
		createRegLabel(0xFFFF26L, "TPU_CH2_P3", 2);
		createRegLabel(0xFFFF28L, "TPU_CH2_P4", 2);
		createRegLabel(0xFFFF2AL, "TPU_CH2_P5", 2);
		createRegLabel(0xFFFF30L, "TPU_CH3_P0", 2);
		createRegLabel(0xFFFF32L, "TPU_CH3_P1", 2);
		createRegLabel(0xFFFF34L, "TPU_CH3_P2", 2);
		createRegLabel(0xFFFF36L, "TPU_CH3_P3", 2);
		createRegLabel(0xFFFF38L, "TPU_CH3_P4", 2);
		createRegLabel(0xFFFF3AL, "TPU_CH3_P5", 2);
		createRegLabel(0xFFFF40L, "TPU_CH4_P0", 2);
		createRegLabel(0xFFFF42L, "TPU_CH4_P1", 2);
		createRegLabel(0xFFFF44L, "TPU_CH4_P2", 2);
		createRegLabel(0xFFFF46L, "TPU_CH4_P3", 2);
		createRegLabel(0xFFFF48L, "TPU_CH4_P4", 2);
		createRegLabel(0xFFFF4AL, "TPU_CH4_P5", 2);
		createRegLabel(0xFFFF50L, "TPU_CH5_P0", 2);
		createRegLabel(0xFFFF52L, "TPU_CH5_P1", 2);
		createRegLabel(0xFFFF54L, "TPU_CH5_P2", 2);
		createRegLabel(0xFFFF56L, "TPU_CH5_P3", 2);
		createRegLabel(0xFFFF58L, "TPU_CH5_P4", 2);
		createRegLabel(0xFFFF5AL, "TPU_CH5_P5", 2);
		createRegLabel(0xFFFF60L, "TPU_CH6_P0", 2);
		createRegLabel(0xFFFF62L, "TPU_CH6_P1", 2);
		createRegLabel(0xFFFF64L, "TPU_CH6_P2", 2);
		createRegLabel(0xFFFF66L, "TPU_CH6_P3", 2);
		createRegLabel(0xFFFF68L, "TPU_CH6_P4", 2);
		createRegLabel(0xFFFF6AL, "TPU_CH6_P5", 2);
		createRegLabel(0xFFFF70L, "TPU_CH7_P0", 2);
		createRegLabel(0xFFFF72L, "TPU_CH7_P1", 2);
		createRegLabel(0xFFFF74L, "TPU_CH7_P2", 2);
		createRegLabel(0xFFFF76L, "TPU_CH7_P3", 2);
		createRegLabel(0xFFFF78L, "TPU_CH7_P4", 2);
		createRegLabel(0xFFFF7AL, "TPU_CH7_P5", 2);
		createRegLabel(0xFFFF80L, "TPU_CH8_P0", 2);
		createRegLabel(0xFFFF82L, "TPU_CH8_P1", 2);
		createRegLabel(0xFFFF84L, "TPU_CH8_P2", 2);
		createRegLabel(0xFFFF86L, "TPU_CH8_P3", 2);
		createRegLabel(0xFFFF88L, "TPU_CH8_P4", 2);
		createRegLabel(0xFFFF8AL, "TPU_CH8_P5", 2);
		createRegLabel(0xFFFF90L, "TPU_CH9_P0", 2);
		createRegLabel(0xFFFF92L, "TPU_CH9_P1", 2);
		createRegLabel(0xFFFF94L, "TPU_CH9_P2", 2);
		createRegLabel(0xFFFF96L, "TPU_CH9_P3", 2);
		createRegLabel(0xFFFF98L, "TPU_CH9_P4", 2);
		createRegLabel(0xFFFF9AL, "TPU_CH9_P5", 2);
		createRegLabel(0xFFFFA0L, "TPU_CH10_P0", 2);
		createRegLabel(0xFFFFA2L, "TPU_CH10_P1", 2);
		createRegLabel(0xFFFFA4L, "TPU_CH10_P2", 2);
		createRegLabel(0xFFFFA6L, "TPU_CH10_P3", 2);
		createRegLabel(0xFFFFA8L, "TPU_CH10_P4", 2);
		createRegLabel(0xFFFFAAL, "TPU_CH10_P5", 2);
		createRegLabel(0xFFFFB0L, "TPU_CH11_P0", 2);
		createRegLabel(0xFFFFB2L, "TPU_CH11_P1", 2);
		createRegLabel(0xFFFFB4L, "TPU_CH11_P2", 2);
		createRegLabel(0xFFFFB6L, "TPU_CH11_P3", 2);
		createRegLabel(0xFFFFB8L, "TPU_CH11_P4", 2);
		createRegLabel(0xFFFFBAL, "TPU_CH11_P5", 2);
		createRegLabel(0xFFFFC0L, "TPU_CH12_P0", 2);
		createRegLabel(0xFFFFC2L, "TPU_CH12_P1", 2);
		createRegLabel(0xFFFFC4L, "TPU_CH12_P2", 2);
		createRegLabel(0xFFFFC6L, "TPU_CH12_P3", 2);
		createRegLabel(0xFFFFC8L, "TPU_CH12_P4", 2);
		createRegLabel(0xFFFFCAL, "TPU_CH12_P5", 2);
		createRegLabel(0xFFFFD0L, "TPU_CH13_P0", 2);
		createRegLabel(0xFFFFD2L, "TPU_CH13_P1", 2);
		createRegLabel(0xFFFFD4L, "TPU_CH13_P2", 2);
		createRegLabel(0xFFFFD6L, "TPU_CH13_P3", 2);
		createRegLabel(0xFFFFD8L, "TPU_CH13_P4", 2);
		createRegLabel(0xFFFFDAL, "TPU_CH13_P5", 2);
		createRegLabel(0xFFFFE0L, "TPU_CH14_P0", 2);
		createRegLabel(0xFFFFE2L, "TPU_CH14_P1", 2);
		createRegLabel(0xFFFFE4L, "TPU_CH14_P2", 2);
		createRegLabel(0xFFFFE6L, "TPU_CH14_P3", 2);
		createRegLabel(0xFFFFE8L, "TPU_CH14_P4", 2);
		createRegLabel(0xFFFFEAL, "TPU_CH14_P5", 2);
		createRegLabel(0xFFFFECL, "TPU_CH14_P6", 2);
		createRegLabel(0xFFFFEEL, "TPU_CH14_P7", 2);
		createRegLabel(0xFFFFF0L, "TPU_CH15_P0", 2);
		createRegLabel(0xFFFFF2L, "TPU_CH15_P1", 2);
		createRegLabel(0xFFFFF4L, "TPU_CH15_P2", 2);
		createRegLabel(0xFFFFF6L, "TPU_CH15_P3", 2);
		createRegLabel(0xFFFFF8L, "TPU_CH15_P4", 2);
		createRegLabel(0xFFFFFAL, "TPU_CH15_P5", 2);
		createRegLabel(0xFFFFFCL, "TPU_CH15_P6", 2);
		createRegLabel(0xFFFFFEL, "TPU_CH15_P7", 2);
	}
}
