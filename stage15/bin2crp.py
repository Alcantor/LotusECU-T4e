#!/usr/bin/python3

import sys, os, struct, xtea

# Valid addresses are:
#  Flash:
#   0xA00 - Payload 12 Bytes (Bootloader config)
#   0xA08 - Payload 4 Bytes (0xFFFFFFFF (Accept unencrypted) -> 0x1 Only CRP)
#   0xA2C - Payload 32 Bytes (Firmware Number)
#   0xA4C - Payload 32 Bytes (ECU Hardware Version)
#   0x10000 - Payload max. size 0x10000 (calrom)
#   0x20000 - Payload max. size 0x5FFFF (prog)
#
#  SPI: 0x7C0, 0x7E0, 0x17C0
#
# Only addresses 0x10000 and 0x20000 can be erased. The other addresses in
# the bootloader are only to upload a new configuration to a blank bootloader.
#
# I don't think you can update the bootloader itself. Only calrom and prog.
#
def bin2crp(bin_file, crp_file, address, bin_offset=0, size=None):
	if(not size): size = os.path.getsize(bin_file) - bin_offset
	print("Convert "+bin_file+" to "+crp_file+".")
	crp_header = struct.pack(
		"<3I32s5I",
		0, # Unknow
		0, # Unknow
		size + 0x40, # Total size (Header + Payload) without padding
		b"T4E                            \0", # Identification string
		address, # Destination Address
		size, # Size of payload
		0, # Min version of bootloader (0 to ignore)
		0, # Max version of bootloader (0 to ignore)
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
	print("BIN to CRP file tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 4 and sys.argv[1] == "calrom"):
		bin2crp(sys.argv[2], sys.argv[3], 0x10000)
	elif(len(sys.argv) >= 4 and sys.argv[1] == "prog"):
		bin2crp(sys.argv[2], sys.argv[3], 0x20000)
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" calrom BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" prog BIN_FILE CRP_FILE")

