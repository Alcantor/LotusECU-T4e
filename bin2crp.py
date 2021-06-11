#!/usr/bin/python3

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

# Some constants
BO_LE = 'little'
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

import sys, os, secrets

class CRP08_exception(Exception):
	pass

class CRP08_xtea():
	def __init__(self):
		self.delta = 0x9E3779B9;
		self.rounds = 32;
		self.mask = 0xFFFFFFFF
		self.key = [
			0x8FCB06DA,
			0xAC193E62,
			0x41500C5C,
			0x64A7B1DB
		]
		self.iv = [0, 0]

	def encrypt(self, v0, v1):
		xsum = 0;
		for i in range(0, self.rounds):
			v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (xsum + self.key[xsum & 3]))) & self.mask
			xsum = (xsum + self.delta) & self.mask
			v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (xsum + self.key[(xsum >> 11) & 3]))) & self.mask
		return v0, v1
	
	def decrypt(self, v0, v1):
		xsum = (self.delta * self.rounds) & self.mask
		for i in range(0, self.rounds):
			v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (xsum + self.key[(xsum >> 11) & 3]))) & self.mask
			xsum = (xsum - self.delta) & self.mask
			v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (xsum + self.key[xsum & 3]))) & self.mask
		return v0, v1
	
	# CBC Encrypt
	def encrypt_cbc(self, buf_in, buf_out):
		last_v0, last_v1 = self.iv
		for i in range(0, len(buf_in), 8):
			v0 = int.from_bytes(buf_in[i:i+4], BO_BE)
			v1 = int.from_bytes(buf_in[i+4:i+8], BO_BE)
			v0 ^= last_v0;
			v1 ^= last_v1;
			v0, v1 = self.encrypt(v0, v1);
			buf_out[i:i+4] = v0.to_bytes(4, BO_BE)
			buf_out[i+4:i+8] = v1.to_bytes(4, BO_BE)
			last_v0 = v0
			last_v1 = v1

	# CBC Decrypt
	def decrypt_cbc(self, buf_in, buf_out):
		last_v0, last_v1 = self.iv
		for i in range(0, len(buf_in), 8):
			c0 = int.from_bytes(buf_in[i:i+4], BO_BE)
			c1 = int.from_bytes(buf_in[i+4:i+8], BO_BE)
			v0, v1 = self.decrypt(c0, c1);
			v0 ^= last_v0;
			v1 ^= last_v1;
			buf_out[i:i+4] = v0.to_bytes(4, BO_BE)
			buf_out[i+4:i+8] = v1.to_bytes(4, BO_BE)
			last_v0 = c0
			last_v1 = c1

	# Calculate the size after padding
	def calc_size(size):
		align = size % 8
		if(align > 0): size += (8-align)
		return size

class BinDataFormat:
	def parse(self, data: memoryview) -> None:
		raise NotImplementedError

	def get_size(self) -> int:
		raise NotImplementedError

	def compose(self, data: memoryview) -> None:
		raise NotImplementedError

class CRP08_chunk_toc(BinDataFormat):
	def __init__(self):
		self.values = [[], []]
		self.ENS = 128

	def parse(self, data):
		self.values = [None] * int.from_bytes(data[0:4], BO_LE)
		for i in range(0, len(self.values)):
			x = 4+(8*i)
			offset = int.from_bytes(data[x:x+4], BO_LE)
			size = int.from_bytes(data[x+4:x+8], BO_LE)
			if(int.from_bytes(data[offset:offset+4], BO_LE) != i+1):
				raise CRP08_exception("CRP index chunk!")
			self.values[i] = [None] * ((size-4) // self.ENS)
			for j in range(0, len(self.values[i])):
				x = offset+4+(self.ENS*j)
				self.values[i][j] = str(data[x:x+self.ENS], CHARSET).rstrip()

	def get_size(self):
		nb_entries = len(self.values)
		size = 4+(8*nb_entries)
		for i in range(0, nb_entries):
			size += 4+(len(self.values[i])*self.ENS)
		return size

	def compose(self, data):
		data[0:4] = len(self.values).to_bytes(4, BO_LE)
		offset = 4+(8*len(self.values))
		for i in range(0, len(self.values)):
			size = 4+(len(self.values[i])*self.ENS)
			x = 4+(8*i)
			data[x:x+4] = offset.to_bytes(4, BO_LE)
			data[x+4:x+8] = size.to_bytes(4, BO_LE)
			data[offset:offset+4] = (i+1).to_bytes(4, BO_LE)
			for j in range(0, len(self.values[i])):
				x = offset+4+(self.ENS*j)
				data[x:x+self.ENS] = bytes(self.values[i][j].ljust(self.ENS), CHARSET)
			offset += size

	def add_entry(self, name, desc):
		self.values[0].append(name)
		self.values[1].append(desc)

	def del_entry(self, index):
		del self.values[0][index]
		del self.values[1][index]

class CRP08_data_ecu(BinDataFormat):
	def __init__(self):
		# Encryption header (12 Bytes)
		self.xtea_salt = secrets.token_bytes(8)
		#self.xtea_plainsize = 76

		# ECU header (64 Bytes)
		self.ecu_id = "T4E"
		self.ecu_addr = 0x10000
		#ecu_binsize = 0
		self.ecu_maxversion = 0
		self.ecu_minversion = 0

		# Binary data
		self.ecu_data = None

	def parse(self, data):
		# Decrypt
		plain = memoryview(bytearray(len(data)))
		CRP08_xtea().decrypt_cbc(data, plain)

		# Encryption header (12 Bytes)
		self.xtea_salt = plain[0:8]
		xtea_plainsize = int.from_bytes(plain[8:12], BO_BE)

		# ECU header (64 Bytes)
		self.ecu_id = str(plain[12:44], CHARSET).rstrip();
		self.ecu_addr = int.from_bytes(plain[44:48], BO_BE)
		ecu_binsize = int.from_bytes(plain[48:52], BO_BE)
		self.ecu_maxversion = int.from_bytes(plain[52:56], BO_BE)
		self.ecu_minversion = int.from_bytes(plain[56:60], BO_BE)

		# Check sizes
		if(xtea_plainsize != ecu_binsize+64):
			raise CRP08_exception("CRP size mismatch!")

		# Binary data
		self.ecu_data = plain[76:76+ecu_binsize]

	def get_size(self):
		return CRP08_xtea.calc_size(76+len(self.ecu_data))

	def compose(self, data):
		plain = memoryview(bytearray(CRP08_xtea.calc_size(76+len(self.ecu_data))))

		# Encryption header (12 Bytes)
		plain[0:8] = self.xtea_salt
		plain[8:12] = (64+len(self.ecu_data)).to_bytes(4, BO_BE)

		# ECU header (64 Bytes)
		plain[12:44] = bytes(self.ecu_id.ljust(32), CHARSET);
		plain[44:48] = self.ecu_addr.to_bytes(4, BO_BE)
		plain[48:52] = len(self.ecu_data).to_bytes(4, BO_BE)
		plain[52:56] = self.ecu_maxversion.to_bytes(4, BO_BE)
		plain[56:60] = self.ecu_minversion.to_bytes(4, BO_BE)

		# Binary data
		plain[76:76+len(self.ecu_data)] = self.ecu_data

		# Encrypt
		CRP08_xtea().encrypt_cbc(plain, data)

	# Export into a BIN file.
	def export_bin(self, file):
		with open(file, 'wb') as f: f.write(self.ecu_data)

	# Import from a BIN file.
	def import_bin(self, file):
		with open(file, 'rb') as f: self.ecu_data = f.read()
		# Remove free space at the end
		self.ecu_data = self.ecu_data.rstrip(b'\xFF')

	def __str__(self):
		fmt = """
CRP08 ECU Data:

	XTEA Salt: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}
	Id.      : {:s}
	Address  : 0x{:5X}
	Size     : 0x{:5X}
	Max Ver. : {:d}
	Min Ver. : {:d}
"""
		return fmt.format(
			*self.xtea_salt,
			self.ecu_id,
			self.ecu_addr,
			len(self.ecu_data),
			self.ecu_maxversion,
			self.ecu_minversion,
		)

class CRP08_chunk_can(BinDataFormat):
	SIGNATURE = 0x0001010A
	
	def __init__(self, is_encrypted):
		# Configuration header (64 Bytes)
		#self.signature = self.SIGNATURE
		self.can_bitrate = 500
		self.can_remote_id1 = 0x50
		self.can_local_id1 = 0x7A0
		self.can_remote_id2 = 0x51
		self.can_local_id2 = 0x7A1

		# Encrypted data
		self.is_encrypted = is_encrypted
		if(self.is_encrypted): self.data = None
		else: self.data = CRP08_data_ecu()

	def parse(self, data):
		# Configuration header (64 Bytes)
		signature = int.from_bytes(data[0:4], BO_LE)
		self.can_bitrate = int.from_bytes(data[4:8], BO_LE)
		self.can_remote_id1 = int.from_bytes(data[8:12], BO_LE)
		self.can_local_id1 = int.from_bytes(data[12:16], BO_LE)
		self.can_remote_id2 = int.from_bytes(data[16:20], BO_LE)
		self.can_local_id2 = int.from_bytes(data[20:24], BO_LE)
		if(signature != self.SIGNATURE):
			raise CRP08_exception("CRP chunk signature!")

		# Encrypted data
		if(self.is_encrypted): self.data = data[64:]
		else: self.data.parse(data[64:])

	def get_size(self):
		if(self.is_encrypted): return 64 + len(self.enc_data)
		else: return 64 + self.data.get_size()

	def compose(self, data):
		# Configuration header (64 Bytes)
		data[0:4] = self.SIGNATURE.to_bytes(4, BO_LE)
		data[4:8] = self.can_bitrate.to_bytes(4, BO_LE)
		data[8:12] = self.can_remote_id1.to_bytes(4, BO_LE)
		data[12:16] = self.can_local_id1.to_bytes(4, BO_LE)
		data[16:20] = self.can_remote_id2.to_bytes(4, BO_LE)
		data[20:24] = self.can_local_id2.to_bytes(4, BO_LE)

		# Encrypted data
		if(self.is_encrypted): data[64:] = self.data
		else: self.data.compose(data[64:])

	def __str__(self):
		fmt = """
CRP08 CAN Chunk:

	Bitrate   : {:d} kbits/s
	Remote ID : 0x{:3X} / 0x{:3X}
	Local ID  : 0x{:3X} / 0x{:3X}
"""
		return fmt.format(
			self.can_bitrate,
			self.can_remote_id1, self.can_remote_id2,
			self.can_local_id1, self.can_local_id2
		) + str(self.data)

class CRP08(BinDataFormat):
	t4e_desc = "LOTUS_T4E_MY08"

	def __init__(self):
		# An empty CRP file
		self.chunks = [CRP08_chunk_toc()]

	def parse(self, data, leave_encrypted=False):
		# Check the sum
		cksum = sum(data[:-2]) & 0xFFFF
		if(cksum != int.from_bytes(data[-2:], BO_LE)):
			raise CRP08_exception("CRP wrong sum!")

		# Parse the chunks
		self.chunks = [None] * int.from_bytes(data[0:4], BO_LE)
		for i in range(0, len(self.chunks)):
			x = 4+(8*i)
			offset = int.from_bytes(data[x:x+4], BO_LE)
			size = int.from_bytes(data[x+4:x+8], BO_LE)
			if(i == 0): chunk = CRP08_chunk_toc()
			else: chunk = CRP08_chunk_can(leave_encrypted)
			chunk.parse(data[offset:offset+size])
			self.chunks[i] = chunk

	def get_size(self):
		size = 4+(8*len(self.chunks))+2
		for chunk in self.chunks:
			size += chunk.get_size()
		return size

	def compose(self, data):
		# Compose the chunks
		data[0:4] = len(self.chunks).to_bytes(4, BO_LE)
		offset = 4+(8*len(self.chunks))
		for i in range(0, len(self.chunks)):
			size = self.chunks[i].get_size()
			x = 4+(8*i)
			data[x:x+4] = offset.to_bytes(4, BO_LE)
			data[x+4:x+8] = size.to_bytes(4, BO_LE)
			self.chunks[i].compose(data[offset:offset+size])
			offset += size

		# Build the sum
		cksum = sum(data[:-2]) & 0xFFFF
		data[-2:] = cksum.to_bytes(2, BO_LE)

	def add_chunk(self, chunk, name, desc):
		# Add the entry into the TOC.
		self.chunks[0].add_entry(name, desc)
		self.chunks.append(chunk)

	def del_chunk(self, index):
		# Delete the entry from the TOC.
		self.chunks[0].del_entry(index-1)
		del self.chunks[index]

	# Create a chunk for the T4E Calibration
	def add_t4e_cal(self, file):
		chk = CRP08_chunk_can(False)
		chk.data.ecu_addr = 0x10000
		chk.data.import_bin(file)
		self.add_chunk(chk, os.path.basename(file), self.t4e_desc)

	# Create a chunk for the T4E Program
	def add_t4e_prog(self, file):
		chk = CRP08_chunk_can(False)
		chk.data.ecu_addr = 0x20000
		chk.data.import_bin(file)
		self.add_chunk(chk, os.path.basename(file), self.t4e_desc)

	# Unpack multiple chunks from a CRP file.
	def read_file(self, file, leave_encrypted=False):
		with open(file, 'rb') as f: self.parse(memoryview(f.read()), leave_encrypted)

	# Pack multiple chunks into a CRP file.
	def write_file(self, file):
		data = memoryview(bytearray(self.get_size()))
		self.compose(data)
		with open(file, 'wb') as f: f.write(data)

if __name__ == "__main__":
	print("BIN to CRP file tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 4 and sys.argv[1] == "calrom"):
		print("Convert "+sys.argv[2]+" into "+sys.argv[3])
		crp = CRP08()
		crp.add_t4e_cal(sys.argv[2])
		crp.write_file(sys.argv[3])
	elif(len(sys.argv) >= 4 and sys.argv[1] == "prog"):
		print("Convert "+sys.argv[2]+" and "+sys.argv[3]+" into "+sys.argv[4])
		crp = CRP08()
		crp.add_t4e_prog(sys.argv[2])
		crp.write_file(sys.argv[3])
	elif(len(sys.argv) >= 5 and sys.argv[1] == "both"):
		print("Convert "+sys.argv[2]+" and "+sys.argv[3]+" into "+sys.argv[4])
		crp = CRP08()
		crp.add_t4e_cal(sys.argv[2])
		crp.add_t4e_prog(sys.argv[3])
		crp.write_file(sys.argv[4])
	elif(len(sys.argv) >= 3 and sys.argv[1] == "unpack"):
		print("Unpack "+sys.argv[2])
		crp = CRP08()
		crp.read_file(sys.argv[2])
		for i in range(1, len(crp.chunks)):
			bin_file = crp.chunks[0].values[0][i-1]
			print("\t into "+bin_file)
			crp.chunks[i].data.export_bin(bin_file)
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" calrom BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" prog BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" both CALROM_BIN_FILE PROG_BIN_FILE CRP_FILE")
		print("\t"+sys.argv[0]+" unpack CRP_FILE")

