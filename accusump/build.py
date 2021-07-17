#!/usr/bin/python3

import sys
sys.path.insert(0, '..')
from lib.ppc32 import PPC32

# Files
acc_file = "accusump.bin"
inp_file = "../dump/t4e-white/A128E6009F/prog.bin" # You cannot change this file without adapting accusump.S, the acis_offsets and oilw_offset variables.
out_file = "prog.bin"

# ACIS Control function to replace with the accusump control
acis_offsets = (0x1BC58, 0x1BD58)

# If we replace the digital oil sensor with an analogic one,
# the oil pressure warning on the cluster will light up constantly!
# We need to patch that too.
oilw_offset = 0x1BAB4
oilw_default = PPC32.ppc_cmpli(0, 0x200) # Threshold at 2.5 V
oilw_new = PPC32.ppc_cmpli(0, 0x0B8) # Threshold at 1.0 bar.

# Build the new program with the accusump control
print("Accusump control builder...")
print("Merge "+acc_file+" and "+inp_file+" into "+out_file)
blank = b"\xFF\xFF\xFF\xFF"
offset = 0
with open(acc_file,'rb') as facc, open(inp_file,'rb') as finp, open(out_file,'wb') as fout:
	while(True):
		chunk = finp.read(4)
		chunk_size = len(chunk)
		if(chunk_size == 0): break # EOF
		if(oilw_offset == offset):
			if(chunk != oilw_default):
				raise Exception("Unexpected default threshold!")
			chunk = oilw_new
		if(acis_offsets[0] <= offset and offset < acis_offsets[1]):
			chunk2 = facc.read(4)
			chunk2_size = len(chunk2)
			chunk = chunk2[0:chunk2_size] + blank[chunk2_size:4]
		fout.write(chunk)
		offset += chunk_size
if(chunk2_size > 0):
	raise Exception("Accusump control is too big!")

# Files
inp_file = "../dump/t4e-white/A128E6009F/calrom.bin"
out_file = "calrom.bin"

table_offsets = (0x3CA0, 0x3CB0)
table_default = bytes([
	0x0A, 0x14, 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50, # RPM
	0x2E, 0x38, 0x43, 0x4D, 0x57, 0x61, 0x6C, 0x6C  # Pressure
])

# Build the new calibration with the accusump default table
print("Accusump calibration builder...")
print("Add accusump table from  "+inp_file+" into "+out_file)
offset = 0
with open(inp_file,'rb') as finp, open(out_file,'wb') as fout:
	while(True):
		chunk = finp.read(4)
		chunk_size = len(chunk)
		if(chunk_size == 0): break # EOF
		if(table_offsets[0] <= offset and offset < table_offsets[1]):
			if(chunk[0:chunk_size] != blank[0:chunk_size]):
				raise Exception("Not enough free space!")
			i = offset-table_offsets[0]
			chunk = table_default[i:i+chunk_size]
		fout.write(chunk)
		offset += chunk_size

