#!/usr/bin/python3

import sys
sys.path.insert(0, '..')
from ppc32 import PPC32

# Bootloader from ALS3M0240J seems ugly. Look at 0x400 for example.
# Bootloader A128E6009F and ALS3M0244F are identical except the ID and CRC.

# Files
s15_file = "../flasher/canstrap.bin"
inp_file = "../dump/A128E6009F/bootldr.bin"
out_file = "bootldr.bin"

# Free space in Bootloader Stage I where to insert the stage 1.5 (canStrap)
s15_offset = 0x3000

# Stage 2 offset
s02_offset = 0x4000

# Opcode to replace in bootloader
old_branch = PPC32.ppc_ba(s02_offset)
new_branch = PPC32.ppc_ba(s15_offset)

# Build the new bootloader with a integrated CAN-Bus flasher
print("Stage 1.5 builder...")
print("Merge "+s15_file+" and "+inp_file+" into "+out_file)
blank = b"\xFF\xFF\xFF\xFF"
offset = 0
with open(s15_file,'rb') as fs15, open(inp_file,'rb') as finp, open(out_file,'wb') as fout:
	while(True):
		chunk = finp.read(4)
		chunk_size = len(chunk)
		if(chunk_size == 0): break # EOF
		if(offset < s15_offset):
			if(chunk == old_branch):
				print("Replace opcode @ "+hex(offset))
				chunk = new_branch
		else:
			chunk2 = fs15.read(4)
			chunk2_size = len(chunk2)
			if(chunk[0:chunk2_size] != blank[0:chunk2_size]):
				raise Exception("Not enough free space!")
			chunk = chunk2 + chunk[chunk2_size:4]
		fout.write(chunk)
		offset += chunk_size

