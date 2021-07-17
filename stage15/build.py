#!/usr/bin/python3

import sys
sys.path.insert(0, '..')
from lib.ppc32 import PPC32

def patch(s15_file, inp_file, out_file, old_branch, new_branch, s15_offset):
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

# Bootloader from ALS3M0240J seems ugly. Look at 0x400 for example.
# Bootloader A128E6009F and ALS3M0244F are identical except the ID and CRC.

# Build the new bootloader with a integrated CAN-Bus flasher
print("Stage 1.5 for white dashboard...")
patch(
	"../flasher/canstrap-white.bin",
	"../dump/t4e-white/A128E6009F/bootldr.bin",
	"white/bootldr.bin",
	PPC32.ppc_ba(0x4000), # This value is also hardcoded in canstrap-white.bin
	PPC32.ppc_ba(0x3000),
	0x3000
)
print("Stage 1.5 for black dashboard...")
patch(
	"../flasher/canstrap-black.bin",
	"../dump/t4e-black/A120E6501F/bootldr.bin",
	"black/bootldr.bin",
	PPC32.ppc_ori(4, 4, 0x1FDC), # This value is also hardcoded in canstrap-black.bin
	PPC32.ppc_ori(4, 4, 0x9000),
	0x9000
)

