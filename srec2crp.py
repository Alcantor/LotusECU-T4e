#!/usr/bin/python3

import sys, random

# Some constants
BO_LE = 'little'
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

class CRP05_exception(Exception):
	pass

# Encryption algorithm:
#
# Note: 2 plain bytes gives 3 encrypted bytes!
#
# K = ~(9744 + (Sum each byte of (CRP Final size)))
#
# w_plain = 2 plain bytes read in little endian
# w_bit_flag = w_plain + K
# w_sum = Sum of table values where the corresponding bit is set in w_bit_flag.
#
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
#
# The key for the T4e (Find in A128E6009F @ sub_6118)
# Mod: 0x5D017 -> 380951
# Mult: 0xC6E -> 3182
# Table:
#   0x7 0xF 0x17 0x2F 0x5D 0xBA 0x174 0x2E8
#   0x5D0 0xBA0 0x1740 0x2E80 0x5D00 0xBA00 0x17401 0x2E801
class CRP05_3by2enc:
	def __init__(self, crp_size):
		# The key for the T4 and T4e
		self.key_mod = 380951
		self.key_mult = 3182
		self.key_table = [
			7, 15, 23, 47,
			93, 186, 372, 744,
			1488, 2976, 5952, 11904,
			23808, 47616, 95233, 190465
		]

		# This value is needed to encrypt and is not stored in the ECU.
		self.key_mult_inv = 62135

		# Convert the length into 4 bytes, sum them all + 9744, and invert
		self.K = ~(9744 + sum(crp_size.to_bytes(4, 'big')))

	# Encrypt data
	def encrypt(self, buf_in, buf_out):
		for i in range(0, len(buf_in)//2, 1):
			x = i*2
			w_plain = int.from_bytes(buf_in[x:x+2], BO_LE)
			w_bit_flag = (w_plain + self.K) & 0xFFFF
			w_sum = 0;
			for j in reversed(range(0, 16)):
				if(w_bit_flag & (1<<j)):
					w_sum += self.key_table[j]
			w_cipher = (w_sum * self.key_mult_inv) % self.key_mod
			w_cipher += (self.key_mod *  random.randint(0, 8))
			x = i*3
			buf_out[x:x+3] = w_cipher.to_bytes(3, BO_LE)

	# Reverse of encrypt()...
	def decrypt(self, buf_in, buf_out):
		for i in range(0, len(buf_in)//3, 1):
			x = i*3
			w_cipher = int.from_bytes(buf_in[x:x+3], BO_LE)
			w_sum = (w_cipher * self.key_mult) % self.key_mod
			w_bit_flag = 0;
			for j in reversed(range(0, 16)):
				if(w_sum >= self.key_table[j]):
					w_sum -= self.key_table[j]
					w_bit_flag |= 1<<j
			if(w_sum != 0): raise CRP05_exception("Wrong Key! @ "+hex(x))
			w_plain = (w_bit_flag - self.K) & 0xFFFF
			x = i*2
			buf_out[x:x+2] = w_plain.to_bytes(2, BO_LE)

	# Compute the needed space for cipher data
	def calc_size_encrypted(size):
		if(size % 2 != 0):
			raise CRP05_exception("Plain size is not 16 bits aligned!")
		return size // 2 * 3;

	# Compute the needed space for plain data
	def calc_size_decrypted(size):
		if(size % 3 != 0):
			raise CRP05_exception("Cipher size is not 24 bits aligned!")
		return size // 3 * 2;

class CRP05_subpacket:
	def __init__(self, addr, data):
		self.addr = addr
		self.data = data

class CRP05_subpackets:
	def __init__(self):
		self.subpackets = []

	def parse(self, data):
		i = 0
		while(i < len(data)):
			if(data[i] == 0xFF):
				# 0xFF are stuffing bytes
				i += 1
			elif(data[i] == 0x55):
				# Extract the Sub-Packet (Very similar to a S-Record line but binary)
				size = data[i+1]
				if(sum(data[i:i+size]) & 0xFF != data[i+size]):
					raise CRP05_Exception("Checksum error of sub-packet")
				addr = int.from_bytes(data[i+2:i+5], BO_BE)
				data2 = data[i+5:i+size]
				i += size+1
				# Add sub-packet
				self.subpackets.append(CRP05_subpacket(addr, data2))
			else:
				raise Exception("Unknow sub-packet "+hex(data_bin[i]))

	def get_size(self):
		size = 0
		for s in self.subpackets: size += 6+len(s.data)
		return size

	def compose(self, data):
		i = 0
		for s in self.subpackets:
			size = 5+len(s.data)
			data[i  ] = 0x55
			data[i+1] = size
			data[i+2:i+5] = s.addr.to_bytes(3, BO_BE)
			data[i+5:i+size] = s.data
			data[i+size] = sum(data[i:i+size]) & 0xFF
			i += size+1

	def __str__(self):
		fmt = """
Subpackets:

	Count : {:d}
"""
		return fmt.format(
			len(self.subpackets)
		)

class CRP05_hdr_ecu_t4:
	def __init__(self):
		self.erase_sector = [False]*8

	def parse(self, data):
		for i in range(0, 8):
			self.erase_sector[i] = True if(data[i+3] > 0) else False

	def get_size(self):
		return 11

	def compose(self, data):
		data[0:3] = b'\x00\x00\x00'
		for i in range(0, 8):
			data[i+3] = 1 if(self.erase_sector[i]) else 0

	def __str__(self):
		fmt = """
T4 Header:

	Erase S0 (Bootloader)  : {:s}
	Erase S1 (Prog)        : {:s}
	Erase S2 (Prog)        : {:s}
	Erase S3 (Prog)        : {:s}
	Erase S4 (Prog)        : {:s}
	Erase S5 (Prog)        : {:s}
	Erase S6 (Prog)        : {:s}
	Erase S7 (Calibration) : {:s}
"""
		return fmt.format(
			*['Yes' if x else 'No' for x in self.erase_sector]
		)

class CRP05_data_ecu:
	def __init__(self):
		# Binary data
		self.header = CRP05_hdr_ecu_t4()
		self.subpackets = CRP05_subpackets()

	def parse(self, data):
		# Decrypt
		plain = memoryview(bytearray(CRP05_3by2enc.calc_size_decrypted(len(data))))
		CRP05_3by2enc(len(data)+20).decrypt(data, plain)

		self.header.parse(plain[0:11])
		self.subpackets.parse(plain[11:-2])
		cksum = int.from_bytes(plain[-2:], BO_LE)

		# Global Checksum
		if(cksum != sum(plain[:-2]) & 0xFFFF):
			raise CRP05_Exception("Wrong Checksum!")

	def get_size(self):
		return CRP05_3by2enc.calc_size_encrypted(14+self.subpackets.get_size())

	def compose(self, data):
		plain = memoryview(bytearray(14+self.subpackets.get_size()))

		self.header.compose(plain[0:11])
		self.subpackets.compose(plain[11:-2])
		cksum = int.from_bytes(plain[-2:], BO_LE) & 0xFFFF
		plain[-2:] = cksum.to_bytes(2, BO_LE)

		# Encrypt
		CRP05_3by2enc(self.get_size()+20).encrypt(plain, data)

	def __str__(self):
		return str(self.header) + str(self.subpackets)

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
class CRP05:
	SIGNATURE = b' EFi'

	def __init__(self, is_encrypted):
		self.desc = ""
		self.is_encrypted = is_encrypted
		if(self.is_encrypted): self.data = None
		else: self.data = CRP05_data_ecu()

	def parse(self, data):
		# Parse the CRP
		crp_size = int.from_bytes(data[0:4], BO_BE)
		self.desc = str(bytes(data[4:16]).rstrip(b'\x00\xFF'), CHARSET)
		if(self.is_encrypted): self.data = data[16:-4]
		else: self.data.parse(data[16:-4])
		signature = data[-4:]

		# Checks
		if(crp_size != len(data)):
			raise CRP05_exception("Header length mismatch")
		if(signature != self.SIGNATURE):
			raise Exception("Wrong Signature")

	def get_size(self):
		if(self.is_encrypted): return 20 + len(self.data)
		else: return 20 + self.data.get_size()

	def compose(self, data):
		crp_size = self.get_size()

		# Compose the CRP
		data[0:4] = crp_size.to_bytes(4, BO_BE)
		data[4:16] = (bytes(self.desc, CHARSET) + b'\x00').ljust(12, b'\xFF')
		if(self.is_encrypted): data[16:-4] = self.data
		else: self.data.compose(data[16:-4])
		data[-4:] = self.SIGNATURE

	# Unpack multiple chunks from a CRP file.
	def read_file(self, file):
		with open(file, 'rb') as f: self.parse(memoryview(f.read()))

	# Pack multiple chunks into a CRP file.
	def write_file(self, file):
		data = memoryview(bytearray(self.get_size()))
		self.compose(data)
		with open(file, 'wb') as f: f.write(data)

	def __str__(self):
		fmt = """
CRP05 K-Line File:

	Description : {:s}
"""
		return fmt.format(
			self.desc
		) + str(self.data)

class CRP:
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


	def srec2crp(srec_file, crp_file, t4_variant):
		# Read the SREC file
		with open(srec_file, 'r') as fsrec:
		  data_srec = fsrec.read()

		# Default S0 Record
		desc = b'CUSTOM CRP'

		# Build sub-packets
		data_bin = bytearray()
		sectors = [False]*8
			

		# Sectors to be erase
		data_bin = CRP.sectors2bin(sectors, t4_variant) + data_bin

		# Global Checksum
		data_bin += (sum(data_bin) & 0xFFFF).to_bytes(2, "little")

		# Write the intermediate file
		#with open("intermediate2.bin", 'wb') as fbin:
		#	fbin.write(data_bin)

		# Compute final size
		size = (len(data_bin) // 2 * 3) + 16 + 4

		# Build the CRP
		data_crp = bytearray()
		data_crp += size.to_bytes(4, "big")
		data_crp += ((desc+b'\x00').ljust(12, b'\xFF'))[0:12]
		data_crp += CRP.encrypt(data_bin, size)
		data_crp += b' EFi'

		# Write the CRP file
		with open(crp_file, 'wb') as fcrp:
			fcrp.write(data_crp)

	# Reverse of srec2crp()...
	def crp2srec(crp_file, srec_file):
		# Read the CRP file
		with open(crp_file, 'rb') as fcrp:
			data_crp = fcrp.read()

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
		

		# Write the SREC file
		with open(srec_file, 'w') as fsrec:
			fsrec.write(data_srec)

if __name__ == "__main__":
	crp = CRP05(False)
	crp.read_file("B120E06H.CRP")
	print(crp)
	crp.write_file("B120E06H-TEST.CRP")
	sys.exit()
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

