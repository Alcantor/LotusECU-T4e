import os, sys, random

# Some constants
BO_LE = 'little'
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

class BinData:
	def parse(self, data: memoryview) -> None:
		raise NotImplementedError
	def get_size(self) -> int:
		raise NotImplementedError
	def compose(self, data: memoryview) -> None:
		raise NotImplementedError

class CRP01_exception(Exception):
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
#
class CRP01_3by2enc:
	K4_KEY = [
		119619,
		20096,
		[
			1, 3, 6, 12,
			25, 48, 100, 200,
			396, 1003, 1800, 3748,
			7350, 15211, 29904, 59809
		],
		125 # This value is needed to encrypt and is not stored in the ECU.
	]
	T4_KEY = [
		380951,
		3182,
		[
			7, 15, 23, 47,
			93, 186, 372, 744,
			1488, 2976, 5952, 11904,
			23808, 47616, 95233, 190465
		],
		62135 # This value is needed to encrypt and is not stored in the ECU.
	]

	def __init__(self, crp_size, key):
		self.key_mod, self.key_mult, self.key_table, self.key_mult_inv = key

		# Convert the length into 4 bytes, sum them all + 9744, and invert
		self.K = ~(9744 + sum(crp_size.to_bytes(4, BO_BE)))

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
			if(w_sum != 0): raise CRP01_exception("Wrong Key! @ "+hex(x))
			w_plain = (w_bit_flag - self.K) & 0xFFFF
			x = i*2
			buf_out[x:x+2] = w_plain.to_bytes(2, BO_LE)

	# Compute the needed space for cipher data
	def calc_size_encrypted(size):
		if(size % 2 != 0):
			raise CRP01_exception("Plain size is not 16 bits aligned!")
		return size // 2 * 3;

	# Compute the needed space for plain data
	def calc_size_decrypted(size):
		if(size % 3 != 0):
			raise CRP01_exception("Cipher size is not 24 bits aligned!")
		return size // 3 * 2;

# K4 Header format:
#
# 00 00 00 s3 s4 s5 s6 FF FF FF FF FF FF FF FF FF
#
# s3 to s6 are bit flags 0x01 or 0x00 to erase the sectors or not.
#
class CRP01_hdr_ecu_k4(BinData):
	def __init__(self):
		self.clear()

	def parse(self, data):
		for i in range(0, 7):
			if(data[i] == 0): self.erase_sector[i] = False
			elif(data[i] == 1): self.erase_sector[i] = True
			else: raise Exception("Invalid header")

	def get_size(self):
		return 16

	def compose(self, data):
		for i in range(0, 7):
			data[i] = 1 if(self.erase_sector[i]) else 0
		data[7:16] = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'

	def clear(self):
		self.erase_sector = [False]*7

	def set_erase_by_addr(self, addr):
		if(addr >= 0x10000):
			sector = 3 + (addr // 0x10000)
		elif(addr >= 0x8000):
			sector = 3
		if(sector < 7): self.erase_sector[sector] = True

	def __str__(self):
		fmt = """
K4 Header:

	Erase S3 (Boot Stage 2) : {:s}
	Erase S4 (Prog)         : {:s}
	Erase S5 (Prog)         : {:s}
	Erase S6 (Calibration)  : {:s}
"""
		return fmt.format(
			*['Yes' if x else 'No' for x in self.erase_sector[3:]]
		)

# T4 Header format:
#
# 00 00 00 s3 s4 s5 s6 s7 s8 s9 s10 FF FF FF FF FF
#
# s3 to s10 are bit flags 0x01 or 0x00 to erase the sectors or not.
#
class CRP01_hdr_ecu_t4(BinData):
	def __init__(self):
		self.clear()

	def parse(self, data):
		for i in range(0, 11):
			if(data[i] == 0): self.erase_sector[i] = False
			elif(data[i] == 1): self.erase_sector[i] = True
			else: raise Exception("Invalid header")

	def get_size(self):
		return 16

	def compose(self, data):
		for i in range(0, 11):
			data[i] = 1 if(self.erase_sector[i]) else 0
		data[11:16] = b'\xFF\xFF\xFF\xFF\xFF'

	def clear(self):
		self.erase_sector = [False]*11

	def set_erase_by_addr(self, addr):
		if(addr >= 0x10000):
			sector = 3 + (addr // 0x10000)
		elif(addr >= 0x8000):
			sector = 3
		if(sector < 11): self.erase_sector[sector] = True

	def __str__(self):
		fmt = """
T4 Header:

	Erase  S3 (Boot Stage 2) : {:s}
	Erase  S4 (Prog)         : {:s}
	Erase  S5 (Prog)         : {:s}
	Erase  S6 (Prog)         : {:s}
	Erase  S7 (Prog)         : {:s}
	Erase  S8 (Prog)         : {:s}
	Erase  S9 (Prog)         : {:s}
	Erase S10 (Calibration)  : {:s}
"""
		return fmt.format(
			*['Yes' if x else 'No' for x in self.erase_sector[3:]]
		)

# T4e Header format:
#
#  T  4  E  _ S0 S2 S1 00 00 00 00 FF FF FF FF FF
#
# S0 to S2 are ASCII flags '1' (0x31) or '0' (0x30) to erase the
# sectors or not. S2 includes sectors 2 to 7.
#
class CRP01_hdr_ecu_t4e(BinData):
	SIGNATURE =  b'T4E_'

	def __init__(self):
		self.clear()

	def parse(self, data):
		signature = data[0:4]
		if(signature != self.SIGNATURE):
			raise Exception("Wrong Signature")
		for i in range(0, 3):
			if(data[i+4] == ord('0')): self.erase_sector[i] = False
			elif(data[i+4] == ord('1')): self.erase_sector[i] = True
			else: raise Exception("Invalid header")

	def get_size(self):
		return 16

	def compose(self, data):
		data[0:4] = self.SIGNATURE
		for i in range(0, 3):
			data[i+4] = ord('1') if(self.erase_sector[i]) else ord('0')
		data[7:16] = b'\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF'

	def clear(self):
		self.erase_sector = [False]*3

	def set_erase_by_addr(self, addr):
		sector = addr // 0x10000
		if(sector == 0): self.erase_sector[0] = True
		elif(sector == 1): self.erase_sector[2] = True
		elif(sector < 8): self.erase_sector[1] = True

	def __str__(self):
		fmt = """
T4e Header:

	Erase S0    (Boot Stage 2) : {:s}
	Erase S2-S7 (Prog)         : {:s}
	Erase S1    (Calibration)  : {:s}
"""
		return fmt.format(
			*['Yes' if x else 'No' for x in self.erase_sector]
		)

# Sub-packets format:
#
#   1 Byte     - Header, always 0x55
#   1 Byte     - Length (Excluging header, including checksum)
#   3 Bytes BE - 24 Bits destination address
#   x Bytes    - Data to write
#   1 Bytes    - Checksum
#
class CRP01_subpackets(BinData):
	def __init__(self):
		self.subpackets = []

	def parse(self, data):
		self.subpackets = []
		i = 0
		while(i < len(data)):
			if(data[i] == 0xFF):
				# 0xFF are stuffing bytes
				i += 1
			elif(data[i] == 0x55):
				# Extract the Sub-Packet (Very similar to a S-Record line but binary)
				size = data[i+1]
				if(sum(data[i:i+size]) & 0xFF != data[i+size]):
					raise CRP01_exception("Checksum error of sub-packet")
				addr = int.from_bytes(data[i+2:i+5], BO_BE)
				data2 = data[i+5:i+size]
				i += size+1
				# Add sub-packet
				self.subpackets.append((addr, data2))
			else:
				raise Exception(f"Unknown sub-packet ({i:d}): 0x{data[i]:02X}")

	def get_size(self):
		size = 0
		for s in self.subpackets: size += 6+len(s[1])
		return size

	def compose(self, data):
		i = 0
		for s in self.subpackets:
			size = 5+len(s[1])
			data[i  ] = 0x55
			data[i+1] = size
			data[i+2:i+5] = s[0].to_bytes(3, BO_BE)
			data[i+5:i+size] = s[1]
			data[i+size] = sum(data[i:i+size]) & 0xFF
			i += size+1

	def delete(self, offset, size):
		limit = offset + size
		self.subpackets = [x for x in self.subpackets if not (offset <= x[0] and x[0] < limit)]

	def export_srec(self, file, desc):
		desc = bytes(desc, CHARSET)
		with open(file, 'w') as f:
			srec_bin  = (len(desc)+3).to_bytes(1, BO_BE)
			srec_bin += b'\x00\x00'
			srec_bin += desc
			srec_bin += (~sum(srec_bin) & 0xFF).to_bytes(1, BO_BE)
			f.write("S0" + ''.join('{:02X}'.format(x) for x in srec_bin) + '\n')
			for s in self.subpackets:
				srec_bin  = (len(s[1])+4).to_bytes(1, BO_BE)
				srec_bin += s[0].to_bytes(3, BO_BE)
				srec_bin += s[1]
				srec_bin += (~sum(srec_bin) & 0xFF).to_bytes(1, BO_BE)
				f.write("S2" + ''.join('{:02X}'.format(x) for x in srec_bin) + '\n')

	def import_srec(self, file):
		desc = ""
		with open(file, 'r') as f:
			data_srec = f.read()
		for line in data_srec.split('\n'):
			if(len(line) < 2 or line[0] != 'S'): continue
			srec_bin = bytearray([int(line[i:i+2], 16) for i in range(2,len(line),2)])
			length = srec_bin[0]
			if(~sum(srec_bin[:length]) & 0xFF != srec_bin[length]):
				raise CRP01_exception("S-Record checksum error")
			if  (line[1] == "0"):
				desc = str(srec_bin[3:length], CHARSET)
				continue
			elif(line[1] == "1"):
				addr = int.from_bytes(srec_bin[1:3], BO_BE)
				data = srec_bin[3:length]
			elif(line[1] == "2"):
				addr = int.from_bytes(srec_bin[1:4], BO_BE)
				data = srec_bin[4:length]
			elif(line[1] == "3"):
				addr = int.from_bytes(srec_bin[1:5], BO_BE)
				data = srec_bin[5:length]
			else:
				continue
			# Build the Sub-Packet
			if(len(data) % 2 != 0):
				raise Exception("S-Record uneven length is incompatible with encryption!")
			self.subpackets.append((addr, data))
		return desc

	def export_bin(self, file, offset, size):
		limit = offset + size
		buf = bytearray([0xFF]*size)
		for s in self.subpackets:
			if not (offset <= s[0] and s[0] < limit): continue
			x = s[0]-offset
			buf[x:x+len(s[1])] = s[1]
		buf = buf.rstrip(b'\xFF')
		with open(file, 'wb') as f:
			f.write(buf)

	# 246 is the maximal size of data in a subpacket.
	def import_bin(self, file, offset, spsize=246):
		with open(file, 'rb') as f:
			buf = f.read()
		self.delete(offset, len(buf))
		# Remove free space
		buf = buf.rstrip(b'\xFF')
		for i in range(0, len(buf), spsize):
			self.subpackets.append((offset+i, buf[i:i+spsize]))

	def __str__(self):
		fmt = """
Subpackets:

	Count : {:d}
"""
		return fmt.format(
			len(self.subpackets)
		)

# Unencrypted data format:
#
#  16 Bytes    - Header
#   x Bytes    - Multiple sub-packets
#   2 Bytes LE - Checksum
#
class CRP01_data_ecu(BinData):
	def __init__(self, hdr, key):
		# Binary data
		self.header = hdr()
		self.key = key
		self.subpackets = CRP01_subpackets()

	def parse(self, data):
		# Decrypt
		plain = memoryview(bytearray(CRP01_3by2enc.calc_size_decrypted(len(data))))
		CRP01_3by2enc(len(data)+20, self.key).decrypt(data, plain)
		self.header.parse(plain[0:16])
		self.subpackets.parse(plain[16:-2])
		cksum = int.from_bytes(plain[-2:], BO_LE)

		# Global Checksum
		if(cksum != sum(plain[:-2]) & 0xFFFF):
			raise CRP01_exception("Wrong Checksum!")

	def get_size(self):
		return CRP01_3by2enc.calc_size_encrypted(18+self.subpackets.get_size())

	def compose(self, data):
		plain = memoryview(bytearray(18+self.subpackets.get_size()))

		self.header.compose(plain[0:16])
		self.subpackets.compose(plain[16:-2])
		cksum = sum(plain[:-2]) & 0xFFFF
		plain[-2:] = cksum.to_bytes(2, BO_LE)

		# Encrypt
		CRP01_3by2enc(self.get_size()+20, self.key).encrypt(plain, data)

	def update_header(self):
		self.header.clear()
		for s in self.subpackets.subpackets:
			self.header.set_erase_by_addr(s[0])

	def __str__(self):
		return str(self.header) + str(self.subpackets)

# CRP 01 Format:
#
#   4 Bytes BE - Total length of CRP file.
#  12 Bytes    - Description (NULL-Terminated + padded with 0xFF)
#   x Bytes    - Encrypted data
#   4 Bytes    - Signature " EFi"
#
class CRP01(BinData):
	SIGNATURE = b' EFi'

	variants = [
		["K4",CRP01_hdr_ecu_k4,CRP01_3by2enc.K4_KEY,0x30000,0x10000,0x10000,0x20000],
		["T4",CRP01_hdr_ecu_t4,CRP01_3by2enc.T4_KEY,0x70000,0x10000,0x10000,0x60000],
		["T4e",CRP01_hdr_ecu_t4e,CRP01_3by2enc.T4_KEY,0x10000,0x10000,0x20000,0x60000]
	]

	def __init__(self, i=0):
		self.desc = "CUSTOM"
		self.is_encrypted = (i == None)
		if(self.is_encrypted): self.data = None
		else: self.data = CRP01_data_ecu(CRP01.variants[i][1], CRP01.variants[i][2])
		self.file_data = b''

	def parse(self, data):
		# Parse the CRP
		crp_size = int.from_bytes(data[0:4], BO_BE)
		self.desc = str(bytes(data[4:16]).rstrip(b'\x00\xFF'), CHARSET)
		if(self.is_encrypted): self.data = data[16:-4]
		else: self.data.parse(data[16:-4])
		signature = data[-4:]

		# Checks
		if(crp_size != len(data)):
			raise CRP01_exception("Header length mismatch")
		if(signature != self.SIGNATURE):
			raise Exception("Wrong Signature")

		# Keep a reference to the complete file
		self.file_data = data

	def get_size(self):
		if(self.is_encrypted): return 20 + len(self.data)
		else: return 20 + self.data.get_size()

	def compose(self, data):
		# Compose the CRP
		crp_size = self.get_size()
		data[0:4] = crp_size.to_bytes(4, BO_BE)
		data[4:16] = (bytes(self.desc, CHARSET) + b'\x00').ljust(12, b'\xFF')
		if(self.is_encrypted): data[16:-4] = self.data
		else: self.data.compose(data[16:-4])
		data[-4:] = self.SIGNATURE

		# Keep a reference to the complete file
		self.file_data = data

	def read_file(self, file):
		with open(file, 'rb') as f: self.parse(memoryview(f.read()))

	def write_file(self, file):
		data = memoryview(bytearray(self.get_size()))
		self.compose(data)
		with open(file, 'wb') as f: f.write(data)

	def __str__(self):
		fmt = """
CRP01 K-Line File:

	Description : {:s}
"""
		return fmt.format(
			self.desc
		) + str(self.data)

if __name__ == "__main__":
	print("SREC to CRP file tool for Lotus K4/T4/T4e ECU\n")
	if(len(sys.argv) >= 2):
		crp = CRP01({"K4": 0, "T4": 1, "T4e": 2}[sys.argv[1]])
	if  (len(sys.argv) >= 5 and sys.argv[2] == "pack"):
		print(f"-- Convert {sys.argv[3]} into {sys.argv[4]} --")
		crp.desc = crp.data.subpackets.import_srec(sys.argv[3])[:11]
		crp.data.update_header()
		crp.write_file(sys.argv[4])
		print(crp)
	elif(len(sys.argv) >= 5 and sys.argv[2] == "unpack"):
		print(f"-- Convert {sys.argv[3]} into {sys.argv[4]} --")
		crp.read_file(sys.argv[3])
		crp.data.subpackets.export_srec(sys.argv[4], crp.desc)
		print(crp)
	else:
		prog = os.path.basename(sys.argv[0])
		print("usage:")
		print(f"\t{prog} [K4|T4|T4e] pack SREC_FILE CRP_FILE")
		print(f"\t{prog} [K4|T4|T4e] unpack CRP_FILE SREC_FILE")

