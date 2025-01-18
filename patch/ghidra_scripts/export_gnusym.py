#@category Symbol
#@menupath Tools.Export.GNUSym
#@description Export user-defined symbols to GNU-compatible .sym file with file save dialog

from ghidra.program.model.symbol import SourceType
import re

# Get the file save location
output_file = askFile("Symbol File", "Save").getAbsolutePath()

# Define a regex pattern for valid symbol names
valid_name = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Open the file for writing
with open(output_file, "w") as file:
	file.write("# GNU Symbol File\n# Exported from Ghidra\n\n")

	# Get the current program and symbol table
	program = currentProgram
	symbol_table = program.getSymbolTable()

	# Iterate through all symbols
	for symbol in symbol_table.getAllSymbols(True):
		if symbol.getSource() == SourceType.USER_DEFINED:
			symbol_name = symbol.getName()
			address = symbol.getAddress().getOffset()
			if(valid_name.match(symbol_name)):
				file.write("{:s} = 0x{:x};\n".format(symbol_name, address))

print("User-defined symbols exported to "+output_file)

