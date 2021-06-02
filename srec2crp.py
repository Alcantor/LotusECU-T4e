#!/usr/bin/python3

import sys, random

class CRP:
	# The key for the T4e (Find in A128E6009F @ sub_6118)
	# Mod: 0x5D017 -> 380951
	# Mult: 0xC6E -> 3182
	# Table:
	#   0x7 0xF 0x17 0x2F 0x5D 0xBA 0x174 0x2E8
	#   0x5D0 0xBA0 0x1740 0x2E80 0x5D00 0xBA00 0x17401 0x2E801

	# The key for the T4 and T4e
	key_mod = 380951
	key_mult = 3182
	key_table = [
		7, 15, 23, 47,
		93, 186, 372, 744,
		1488, 2976, 5952, 11904,
		23808, 47616, 95233, 190465
	]

	# This value is needed to encrypt and is not stored in the ECU.
	key_mult_inv = 62135

	# The reverse of:
	#   w_sum = (w_cipher * CRP.key_mult) % CRP.key_mod
	# is:
	#   w_cipher = (w_sum * CRP.key_mult_inv) % CRP.key_mod
	#
	# A random value is added to obfuscate the result:
	#   w_cipher += (CRP.key_mod *  random.randint(0, 8))
	#
	# Decrypt: 372 = (257160 * 3182) % 380951
	# Encrypt: 257160 = (372 * 62135) % 380951

	# The first 16 bytes of the unencrypted data, are a list of
	# sectors to be erase.
	#
	# T4 : 00 00 00 s0 s1 s2 s3 s4 s5 s6 s7 FF FF FF FF FF
	# T4e:  T  4  E  _ S0 S2 S1 00 00 00 00 FF FF FF FF FF
	#
	# s0 to s7 are bit flags 0x01 or 0x00 to erase the sectors or not.
	# S0 to S2 are ASCII flags '1' (0x31) or '0' (0x30) to erase the
	# sectors or not. S2 includes sectors 2 to 7.
	#
	# The remaining 0xFF are optional padding bytes.
	def sectors2bin(sectors, t4_variant):
		if(t4_variant):
			print("--> T4 ECU <--")
			for i in range(0, len(sectors)):
				if(sectors[i]):	print("Sector "+str(i)+" will be erased!")
			return b'\x00'*3 + bytes(sectors) + b'\xFF'*5
		else:
			print("--> T4E ECU <--")
			sectors = [sectors[0],max(sectors[2:]),sectors[1]]
			if(sectors[0]): print("Block 0 (Bootloader) will be erased!")
			if(sectors[1]): print("Block 2-7 (Prog) will be erased!")
			if(sectors[2]): print("Block 1 (Calibration) will be erased!")
			sectors = [i+ord('0') for i in sectors]
			return b'T4E_' + bytes(sectors) + b'\x00'*4 + b'\xFF'*5

	# Reverse of sectors2bin()...
	def bin2sectors(data_bin):
		if(data_bin[0:3] == b'\x00' * 3):
			print("--> T4 ECU <--")
			sectors = data_bin[3:11]
			# data_bin[11:16] == b'\xFF'*5
			for i in range(0, len(sectors)):
				if(sectors[i]):	print("Sector "+str(i)+" must be erased!")
			return sectors
		elif(data_bin[0:4] == b'T4E_'):
			print("--> T4E ECU <--")
			sectors = data_bin[4:7]
			# data_bin[7:16] == b'\x00'*4 + b'\xFF'*5
			sectors = [i-ord('0') for i in sectors]
			if(sectors[0]): print("Block 0 (Bootloader) must be erased!")
			if(sectors[1]): print("Block 2-7 (Prog) must be erased!")
			if(sectors[2]): print("Block 1 (Calibration) must be erased!")
			sectors = [sectors[0],sectors[2]]+[sectors[1]]*6
			return sectors
		else:
			raise Exception("Unknow file variant!")

	# CRP Format:
	#
	#   4 Bytes BE - Total length of CRP file.
	#  12 Bytes    - Description (NULL-Terminated + padded with 0xFF)
	#   x Bytes    - Encrypted data
	#   4 Bytes    - Signature " EFi"
	#
	# Unencrypted data format:
	#
	#  11 Bytes    - Sectors to erase
	#   5 Bytes    - Padding bytes 0xFF (optional)
	#   x Bytes    - Multiple sub-packets
	#   2 Bytes LE - Checksum
	#
	# Sub-packets format:
	#
	#   1 Byte     - Header, always 0x55
	#   1 Byte     - Length (Excluging header, including checksum)
	#   3 Bytes BE - 24 Bits destination address
	#   x Bytes    - Data to write
	#   1 Bytes    - Checksum
	def srec2crp(srec_file, crp_file, t4_variant):
		# Read the SREC file
		with open(srec_file, 'r') as fsrec:
		  data_srec = fsrec.read()

		# Default S0 Record
		desc = b'CUSTOM CRP'

		# Build sub-packets
		data_bin = bytearray()
		sectors = [False]*8
		for line in data_srec.split('\n'):
			# Read the SREC Line
			if(len(line) < 2 or line[0] != 'S'): continue
			srec_bin = bytearray([int(line[j:j+2], 16) for j in range(2,len(line),2)])
			length = srec_bin[0]
			if(~sum(srec_bin[:length]) & 0xFF != srec_bin[length]):
				raise Exception("S-Record checksum error")
			if  (line[1] == "0"):
				desc = srec_bin[3:length]
			elif(line[1] == "1"):
				raise Exception("This script doesn't support S1 format... Sorry...")
			elif(line[1] == "2"):
				address = srec_bin[1:4]
				data = srec_bin[4:length]
				# Build the Sub-Packet
				if(length % 2 != 0):
					raise Exception("S-Record uneven length is incompatible with encryption!")
				sub = b'\x55' + (length+1).to_bytes(1, "big") + address + data
				data_bin += sub + (sum(sub) & 0xFF).to_bytes(1, "big")
				# Sectors ?
				sector = int.from_bytes(address, "big") // 0x10000
				if(sector < len(sectors)): sectors[sector] = True
			elif(line[1] == "3"):
				raise Exception("This script doesn't support S3 format... Sorry...")
		print("SREC for " + desc.decode())

		# Sectors to be erase
		data_bin = CRP.sectors2bin(sectors, t4_variant) + data_bin

		# Global Checksum
		data_bin += (sum(data_bin) & 0xFFFF).to_bytes(2, "little")

		# Write the intermediate file
		#with open("intermediate2.bin", 'wb') as fbin:
		#	fbin.write(data_bin)

		# Compute final size
		size = (len(data_bin) // 2 * 3) + 16 + 4

		# Header
		data_crp = bytearray()
		data_crp += size.to_bytes(4, "big")
		data_crp += ((desc+b'\x00').ljust(12, b'\xFF'))[0:12]

		# Convert the length into 4 bytes, sum them all + 9744, and invert
		K = ~(9744 + sum(size.to_bytes(4, 'big')))

		# Encrypt
		for i in range(0, len(data_bin), 2):
			w_plain = int.from_bytes(data_bin[i:i+2], "little")
			w_bit_flag = w_plain + K
			w_sum = 0;
			for j in reversed(range(0, 16)):
				if(w_bit_flag & (1<<j)):
					w_sum += CRP.key_table[j]
			w_cipher = (w_sum * CRP.key_mult_inv) % CRP.key_mod
			w_cipher += (CRP.key_mod *  random.randint(0, 8))
			data_crp += w_cipher.to_bytes(3, "little")

		# Footer
		data_crp += b' EFi'

		# Write the CRP file
		with open(crp_file, 'wb') as fcrp:
			fcrp.write(data_crp)

	# Reverse of srec2crp()...
	def crp2srec(crp_file, srec_file):
		# Read the CRP file
		with open(crp_file, 'rb') as fcrp:
			data_crp = fcrp.read()

		# Header and Footer
		if(data_crp[-4:] != b' EFi'):
			raise Exception("Wrong Signature")
		if(int.from_bytes(data_crp[0:4], "big") != len(data_crp)):
			raise Exception("Header length mismatch")
		if((len(data_crp)-16-4) % 3 != 0):
			raise Exception("Length is not 24 bits aligned!")

		# 12 bytes string null terminated and padded with 0xFF
		desc = data_crp[4:16].rstrip(b'\x00\xFF')
		print("CRP for " + desc.decode())

		# Convert the length into 4 bytes, sum them all + 9744, and invert
		K = ~(9744 + sum(len(data_crp).to_bytes(4, 'big')))

		# Decrypt
		data_bin = bytearray()
		for i in range(16, len(data_crp)-4, 3):
			w_cipher = int.from_bytes(data_crp[i:i+3], "little")
			w_sum = (w_cipher * CRP.key_mult) % CRP.key_mod
			w_bit_flag = 0;
			for j in reversed(range(0, 16)):
				if(w_sum >= CRP.key_table[j]):
					w_sum -= CRP.key_table[j]
					w_bit_flag |= 1<<j
			if(w_sum != 0): raise Exception("Wrong Key! @ "+hex(i))
			w_plain = (w_bit_flag - K) & 0xFFFF
			data_bin += w_plain.to_bytes(2, "little")

		# Global Checksum
		if(sum(data_bin[:-2]) & 0xFFFF != int.from_bytes(data_bin[-2:], "little")):
			raise Exception("Wrong Checksum!")

		# Write the intermatiade file
		#with open("intermediate.bin", 'wb') as fbin:
		#	fbin.write(data_bin)

		# Sectors to be erase
		CRP.bin2sectors(data_bin)

		# S0 Record
		srec_bin = (2+len(desc)+1).to_bytes(1, "big") + b'\x00\x00' + desc
		srec_bin += (~sum(srec_bin) & 0xFF).to_bytes(1, "big")
		data_srec = "S0" + ''.join('{:02X}'.format(x) for x in srec_bin) + '\n'

		# Read sub-packets
		i = 11
		while(i < len(data_bin)-2):
			if(data_bin[i] == 0xFF):
				# 0xFF are stuffing bytes ?
				i += 1
			elif(data_bin[i] == 0x55):
				# Extract the Sub-Packet (Very similar to a S-Record line but binary)
				length = data_bin[i+1]
				if(sum(data_bin[i:i+length]) & 0xFF != data_bin[i+length]):
					raise  Exception("Checksum error of sub-packet")
				address = data_bin[i+2:i+5]
				data = data_bin[i+5:i+length]
				# Build the SREC Line
				srec_bin = (length-1).to_bytes(1, "big") + address + data
				srec_bin += (~sum(srec_bin) & 0xFF).to_bytes(1, "big")
				data_srec += "S2" + ''.join('{:02X}'.format(x) for x in srec_bin) + '\n'
				i += length+1
			else:
				raise Exception("Unknow sub-packet "+hex(data_bin[i]))

		# Write the SREC file
		with open(srec_file, 'w') as fsrec:
			fsrec.write(data_srec)

if __name__ == "__main__":
	print("SREC to CRP file tool for Lotus T4/T4E ECU\n")
	if  (len(sys.argv) >= 4 and sys.argv[1] == "pack"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3]+"\n")
		CRP.srec2crp(sys.argv[2], sys.argv[3], True)
	elif(len(sys.argv) >= 4 and sys.argv[1] == "pack_t4e"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3]+"\n")
		CRP.srec2crp(sys.argv[2], sys.argv[3], False)
	elif(len(sys.argv) >= 4 and sys.argv[1] == "unpack"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3]+"\n")
		CRP.crp2srec(sys.argv[2], sys.argv[3])
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" pack SREC_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" pack_t4e SREC_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" unpack CRP_FILE SREC_FILE")

