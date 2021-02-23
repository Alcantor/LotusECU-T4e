#!/usr/bin/python3

import os, struct, xtea

# Valid addresses are:
#  Flash:
#   0xA00 - Payload 12 Bytes (Bootloader config?)
#   0xA08 - ?
#   0xA2C - Payload 32 Bytes (Firmware Number)
#   0xA4C - Payload 32 Bytes (ECU Hardware Version)
#   0x10000 - Payload max. size 0x10000 (calrom)
#   0x20000 - Payload max. size 0x5FFFF (prog)
#
#  SPI: 0x7C0, 0x7E0, 0x17C0
#
def bin2crp(bin_file, crp_file, address, bin_offset=0, size=None):
	if(not size): size = os.path.getsize(bin_file) - bin_offset
	crp_header = struct.pack(
		"<3I32s5I",
		0, # Unknow
		0, # Unknow
		size + 0x40, # Total size (Header + Payload + Padding)
		b"T4E                            \0", # Identification string
		address, # Destination Address
		size, # Size of payload
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
		rounds=64, # 64 Rounds, 32 Cycles
		iv=bytes([0,0,0,0,0,0,0,0])
	)

	with open(bin_file, 'rb') as fbin, open(crp_file, 'wb') as fcrp:
		fcrp.write(x.encrypt(crp_header))
		fbin.seek(bin_offset)
		while(size > 0):
				chunk_size = min(1024, size)
				chunk = fbin.read(chunk_size)
				fcrp.write(x.encrypt(chunk))
				size -= chunk_size

if __name__ == "__main__":
	print("Convert black stage 15 into a CRP File...")
	print("\nUNTESTED! Do NOT use!\n")
	bin2crp(
		"black/bootldr.bin",
		"black/bootldr.crp",
		0xA00,
		0xA00,
		0x9000-0xA00+512 # Max 512 bytes canstrap-black.bin
	)

