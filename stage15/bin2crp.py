#!/usr/bin/python3

import os, struct, xtea

def bin2crp(bin_file, crp_file, address, bin_offset=0):
	size = os.path.getsize(bin_file) - bin_offset
	crp_header = struct.pack(
		"<3I32s5I",
		0, # Unknow
		0, # Unknow
		0, # Unknow
		b"T4E                            \0", # Identification string
		address, # Destination Address (0xA00, 0x10000, 0x20000, ...)
		size, # Length
		11240, # Min version of bootloader
		11240, # Max version of bootloader
		0 # Unknow
	)

	x = xtea.new(
		bytes([
			0x8F, 0xCB, 0x06, 0xDA, 0xAC, 0x19, 0x3E, 0x62,
			0x41, 0x50, 0x0C, 0x5C, 0x64, 0xA7, 0xB1, 0xDB
		]),
		mode=xtea.MODE_CBC,
		rounds=32,
		iv=bytes([0,0,0,0,0,0,0,0])
	)

	with open(bin_file, 'rb') as fbin, open(crp_file, 'wb') as fcrp:
		fcrp.write(x.encrypt(crp_header))
		fbin.seek(bin_offset)
		while(True):
				chunk = fbin.read(1024)
				chunk_size = len(chunk)
				if(chunk_size == 0): break # EOF
				fcrp.write(x.encrypt(chunk))

if __name__ == "__main__":
	print("Convert black stage 15 into a CRP File...")
	print("\nUNTESTED! Do NOT use!\n")
	bin2crp(
		"black/bootldr.bin",
		"black/bootldr.crp",
		0xA00,
		0xA00
	)

