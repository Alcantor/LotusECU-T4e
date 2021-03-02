#!/usr/bin/python3

import sys, secrets, xtea

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
def bin2chunk(bin_file, address, bin_offset=0, size=None):
	print("Convert "+bin_file)

	# Guess size
	if(not size):
		size = 0
		with open(bin_file, 'rb') as fbin:
			while(True):
				byte = fbin.read(1)
				if(len(byte) == 0): break # EOF
				if(byte[0] != 0xFF): size = fbin.tell()
		print("Auto-Trim free space @ "+hex(size))
		size -= bin_offset

	# Normal Header + Data
	with open(bin_file, 'rb') as fbin:
		fbin.seek(bin_offset)
		chk_data = fbin.read(size)
	chk_data = b''.join([
		b"T4E".ljust(31), b'\x00', # Identification string
		address.to_bytes(4, "big"), # Destination Address
		len(chk_data).to_bytes(4, "big"), # Size of payload
		(0).to_bytes(4, "big"), # Max version of bootloader (0 to ignore)
		(0).to_bytes(4, "big"), # Min version of bootloader (0 to ignore)
		b'\x00' * 16, # 16 Padding bytes
		chk_data # Payload
	])

	# Encryption Header + Data
	chk_data = b''.join([
		# b'\x00' * 8, # No Salt
		secrets.token_bytes(8), # Encryption Salt (Random numbers)
		len(chk_data).to_bytes(4, "big"), # Size of plain data
		chk_data # Plain data
	])

	# Padding bytes for XTEA
	crp_align = len(chk_data) % 8
	if(crp_align > 0): chk_data += b'\xFF' * (8-crp_align)

	# XTEA Encryption
	x = xtea.new(
		bytes([
			0x8F, 0xCB, 0x06, 0xDA, 0xAC, 0x19, 0x3E, 0x62,
			0x41, 0x50, 0x0C, 0x5C, 0x64, 0xA7, 0xB1, 0xDB
		]),
		mode=xtea.MODE_CBC,
		rounds=64, # 64 Rounds, 32 Cycles
		iv=bytes([0,0,0,0,0,0,0,0])
	)
	return x.encrypt(chk_data)

def chunk2crp(crp_file, crp_chunks):
	# Add chunk header
	nb_crp_chunks = 1 + len(crp_chunks)
	offset = 4+(8*nb_crp_chunks)
	crp_header = [
		nb_crp_chunks.to_bytes(4, "little"), # Nb of chunks
		# First chunk: This header
		(0).to_bytes(4, "little"), # Offset
		offset.to_bytes(4, "little") # Length
	]
	for chunk in crp_chunks:
		crp_header += [
			offset.to_bytes(4, "little"), # Offset
			len(chunk).to_bytes(4, "little") # Length
		]
		offset += len(chunk)

	# Concat header + all chunks
	crp_data = b''.join(crp_header + crp_chunks)

	# Add final checksum
	cksum = 0
	for b in crp_data: cksum += b
	cksum &= 0xFFFF
	crp_data += cksum.to_bytes(2, "little")

	# Create CRP file
	with open(crp_file, 'wb') as fcrp:
		fcrp.write(crp_data)

if __name__ == "__main__":
	print("BIN to CRP file tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 4 and sys.argv[1] == "calrom"):
		chunk2crp(sys.argv[3], [
			bin2chunk(sys.argv[2], 0x10000)
		])
	elif(len(sys.argv) >= 4 and sys.argv[1] == "prog"):
		chunk2crp(sys.argv[3], [
			bin2chunk(sys.argv[2], 0x20000)
		])
	elif(len(sys.argv) >= 5 and sys.argv[1] == "both"):
		chunk2crp(sys.argv[4], [
			bin2chunk(sys.argv[2], 0x10000),
			bin2chunk(sys.argv[3], 0x20000)
		])
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" calrom BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" prog BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" both CALROM_BIN_FILE PROG_BIN_FILE CRP_FILE")

