#!/usr/bin/python3

import sys, secrets, xtea

class CRPException(Exception):
	pass

class CRP:
	# Encryption algorithm
	def xtea():
		return xtea.new(
			bytes([
				0x8F, 0xCB, 0x06, 0xDA, 0xAC, 0x19, 0x3E, 0x62,
				0x41, 0x50, 0x0C, 0x5C, 0x64, 0xA7, 0xB1, 0xDB
			]),
			mode=xtea.MODE_CBC,
			rounds=64, # 64 Rounds, 32 Cycles
			iv=bytes([0,0,0,0,0,0,0,0])
		)

	# The first chunk of a CRP data is an index with original filenames and descriptions.
	def info2chunk(infos):
		subchunk_names = b''.join(
			[(1).to_bytes(4, "little")] +
			[x['name'].encode().ljust(0x80) for x in infos]
		)
		subchunk_descs = b''.join(
			[(2).to_bytes(4, "little")] +
			[x['desc'].encode().ljust(0x80) for x in infos]
		)
		return b''.join([
			(2).to_bytes(4, "little"), # 2 Sub-chunk
			(0x14).to_bytes(4, "little"), # Offset 1
			len(subchunk_names).to_bytes(4, "little"), # Length 1
			(0x14+len(subchunk_names)).to_bytes(4, "little"), # Offset 2
			len(subchunk_descs).to_bytes(4, "little"), # Length 2
			subchunk_names, subchunk_descs
		])

	def chunk2info(chunk0):
		if(int.from_bytes(chunk0[0:4], "little") != 2):
			raise CRPException("CRP index chunk!")
		offset1 = int.from_bytes(chunk0[4:8], "little")
		length1 = int.from_bytes(chunk0[8:12], "little")
		offset2 = int.from_bytes(chunk0[12:16], "little")
		length2 = int.from_bytes(chunk0[16:20], "little")
		if(length1 != length2):
			raise CRPException("CRP index chunk!")
		infos = []
		for i in range(4, length1, 0x80):
			infos.append({
				'name': chunk0[offset1+i:offset1+i+0x80].decode().rstrip(),
				'desc': chunk0[offset2+i:offset2+i+0x80].decode().rstrip()
			})
		return infos

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
	def bin2chunk(bin_file, address, bin_offset=0, size=None, ecu_id_str=b"T4E"):
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

		# Normal Header (64 Bytes) + Data
		with open(bin_file, 'rb') as fbin:
			fbin.seek(bin_offset)
			chk_data = fbin.read(size)
		chk_data = b''.join([
			ecu_id_str.ljust(31), b'\x00', # Identification string
			address.to_bytes(4, "big"), # Destination Address
			len(chk_data).to_bytes(4, "big"), # Size of payload
			(0).to_bytes(4, "big"), # Max version of bootloader (0 to ignore)
			(0).to_bytes(4, "big"), # Min version of bootloader (0 to ignore)
			b'\x00' * 16, # 16 Padding bytes
			chk_data # Payload
		])

		# Encryption Header (12 Bytes) + Data
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
		# At this point, we have the data as expected by the bootloader.
		chk_data = CRP.xtea().encrypt(chk_data)

		# Add CAN-Bus configuration (64 Bytes) + Data
		# This is only valid for an ECU. Not a transmission controller.
		return b''.join([
			(0x0001010A).to_bytes(4, "little"), # Unknow
			(500).to_bytes(4, "little"), # CAN-Bus bitrate
			(0x50).to_bytes(4, "little"), # CAN-Bus remote ID1
			(0x7A0).to_bytes(4, "little"), # CAN-Bus local ID1
			(0x51).to_bytes(4, "little"), # CAN-Bus remote ID2
			(0x7A1).to_bytes(4, "little"), # CAN-Bus local ID2
			b'\x00' * 40, # 40 Padding bytes
			chk_data # Payload
		])

	# Reverse of bin2chunk()...
	def chunk2bin(bin_file, chk_data):
		chk_data = CRP.xtea().decrypt(chk_data[0x40:])
		length = int.from_bytes(chk_data[0x30:0x34], "big")
		with open(bin_file, 'wb') as fbin:
			fbin.write(chk_data[0x4C:0x4C+length])

	# Pack multiple chunks into a CRP file.
	def chunk2crp(crp_file, crp_chunks):
		# Add chunk header (4+8*x Bytes)
		nb_crp_chunks = len(crp_chunks)
		offset = 4+(8*nb_crp_chunks)
		crp_header = [nb_crp_chunks.to_bytes(4, "little")] # Nb of chunks
		for chunk in crp_chunks:
			crp_header += [
				offset.to_bytes(4, "little"), # Offset
				len(chunk).to_bytes(4, "little") # Length
			]
			offset += len(chunk)

		# Concat header + all chunks
		crp_data = b''.join(crp_header + crp_chunks)

		# Add final checksum
		cksum = sum(crp_data) & 0xFFFF
		crp_data += cksum.to_bytes(2, "little")

		# Create CRP file
		with open(crp_file, 'wb') as fcrp:
			fcrp.write(crp_data)

	# Unpack multiple chunks from a CRP file.
	def crp2chunk(crp_file):
		with open(crp_file, 'rb') as fcrp:
			crp_data = fcrp.read()

		# Check the sum
		cksum = sum(crp_data[:-2]) & 0xFFFF
		if(cksum != int.from_bytes(crp_data[-2:], "little")):
			raise CRPException("CRP wrong sum!")

		# Extract the chunks
		crp_chunks = []
		nb_crp_chunks = int.from_bytes(crp_data[0:4], "little")
		for i in range(0, nb_crp_chunks):
			x = 4+(8*i)
			offset = int.from_bytes(crp_data[x:x+4], "little")
			size = int.from_bytes(crp_data[x+4:x+8], "little")
			crp_chunks.append(crp_data[offset:offset+size])
		return crp_chunks

if __name__ == "__main__":
	print("BIN to CRP file tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 4 and sys.argv[1] == "calrom"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3])
		CRP.chunk2crp(sys.argv[3], [
			CRP.info2chunk([
				{'name': "calrom.bin", 'desc': "CUSTOM CALROM"}
			]),
			CRP.bin2chunk(sys.argv[2], 0x10000)
		])
	elif(len(sys.argv) >= 4 and sys.argv[1] == "prog"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3])
		CRP.chunk2crp(sys.argv[3], [
			CRP.info2chunk([
				{'name': "prog.bin", 'desc': "CUSTOM PROG"}
			]),
			CRP.bin2chunk(sys.argv[2], 0x20000)
		])
	elif(len(sys.argv) >= 5 and sys.argv[1] == "both"):
		print("Convert "+sys.argv[2]+" and "+sys.argv[3]+" into "+sys.argv[4])
		CRP.chunk2crp(sys.argv[4], [
			CRP.info2chunk([
				{'name': "calrom.bin", 'desc': "CUSTOM CALROM"},
				{'name': "prog.bin", 'desc': "CUSTOM PROG"}
			]),
			CRP.bin2chunk(sys.argv[2], 0x10000),
			CRP.bin2chunk(sys.argv[3], 0x20000)
		])
	elif(len(sys.argv) >= 3 and sys.argv[1] == "unpack"):
		print("Unpack "+sys.argv[2])
		crp_chunks = CRP.crp2chunk(sys.argv[2])
		infos = CRP.chunk2info(crp_chunks[0])
		for i in range(1, len(crp_chunks)):
			bin_file = infos[i-1]['name']
			print("\t into "+bin_file)
			CRP.chunk2bin(bin_file, crp_chunks[i])
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" calrom BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" prog BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" both CALROM_BIN_FILE PROG_BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" unpack CRP_FILE")

