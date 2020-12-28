#!/usr/bin/python3

import os

def ppc_cmplwi_opcode(register, immediate):
	opcode     = bytearray([0x28, 0x00, 0x00, 0x00])
	opcode[1] |= register & 0x1F
	opcode[2] |= (immediate >>  8) & 0xFF
	opcode[3] |= immediate & 0xFF
	return opcode

# Files
acc_file = "accusump.bin"
inp_file = "../dump/ALS3M0244F/prog.bin" # You cannot change this file without adapting accusump.S and the acis_offsets variable
out_file = "prog.bin"

# ACIS Control function to replace with the accusump control
acis_offsets = (0x19690, 0x19790)

# If we replace the digital oil sensor with an analogic one,
# the oil pressure warning on the cluster will light up constantly!
# We need to patch that too.
oilw_offset = 0x194EC
oilw_default = ppc_cmplwi_opcode(0, 0x200) # Threshold at 2.5 V
oilw_new = ppc_cmplwi_opcode(0, 0x100) # Threshold at 2.5 bar? (1024/10*2.5)

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
inp_file = "../dump/A128E6009F/calrom.bin"
out_file = "calrom.bin"

table_offsets = (0x3CA0, 0x3CB0)
table_default = bytes([
	0x05, 0x0A, 0x0F, 0x14, 0x19, 0x1E, 0x23, 0x28, # RPM
	0x40, 0x4D, 0x59, 0x66, 0x73, 0x80, 0xCC, 0xCC  # Pressure
])

# Build the new calibration with the accusump default table
print("Accusump calibration builder...")
print("Add accusump table from  "+inp_file+" into "+out_file)
blank = b"\xFF\xFF\xFF\xFF"
offset = 0
with open(inp_file,'rb') as finp, open(out_file,'wb') as fout:
	while(True):
		chunk = finp.read(4)
		chunk_size = len(chunk)
		if(chunk_size == 0): break # EOF
		if(table_offsets[0] <= offset and offset < table_offsets[1]):
			i = offset-table_offsets[0]
			chunk = table_default[i:i+4]
		fout.write(chunk)
		offset += chunk_size

