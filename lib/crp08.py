import os, sys, secrets

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

class CRP08_exception(Exception):
	pass

# Encryption algorithm:
#
# Standard XTEA. XTEA data size needs to be a mulitple of 8 bytes. So padding
# is required.
#
class CRP08_xtea():
	T4E_KEY = [0x8FCB06DA,0xAC193E62,0x41500C5C,0x64A7B1DB]
	T6_KEY = [0x340D2EB9,0xC41A93EE,0x73FAFED5,0x47C80F57]
	T6_CATERHAM_KEY = [0x340B2EB9,0xC51A93EE,0x73EAFED5,0x47C80F53]
	T6_YARIS_KEY = [0xAFA89C03, 0x520CC120, 0x3E20902A, 0x2338E27C]

	def __init__(self, key):
		self.delta = 0x9E3779B9;
		self.rounds = 32;
		self.mask = 0xFFFFFFFF
		self.key = key
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

# The first chunk of a CRP data contains a kind of "Table of Content" for the
# next chunks.
#
# Chunk TOC format:
#
#   4 Bytes LE - Sould always be 2
#   4 Bytes LE - Offset of the file list
#   4 Bytes LE - Size of the file list
#   4 Bytes LE - Offset of description list
#   4 Bytes LE - Size of the description list
#
# File list format:
#   4 Bytes LE - Sould always be 1
#   x Bytes    - File list (Each element is 128 Bytes long)
#
# File description format:
#   4 Bytes LE - Sould always be 2
#   x Bytes    - File list (Each element is 128 Bytes long)
#
class CRP08_chunk_toc(BinData):
	def __init__(self):
		self.toc_values = [[], []]
		self.ENS = 128

	def parse(self, data):
		self.toc_values = [None] * int.from_bytes(data[0:4], BO_LE)
		for i in range(0, len(self.toc_values)):
			x = 4+(8*i)
			offset = int.from_bytes(data[x:x+4], BO_LE)
			size = int.from_bytes(data[x+4:x+8], BO_LE)
			if(int.from_bytes(data[offset:offset+4], BO_LE) != i+1):
				raise CRP08_exception("Index chunk!")
			self.toc_values[i] = [None] * ((size-4) // self.ENS)
			for j in range(0, len(self.toc_values[i])):
				x = offset+4+(self.ENS*j)
				self.toc_values[i][j] = str(data[x:x+self.ENS], CHARSET).rstrip()

	def get_size(self):
		nb_entries = len(self.toc_values)
		size = 4+(8*nb_entries)
		for i in range(0, nb_entries):
			size += 4+(len(self.toc_values[i])*self.ENS)
		return size

	def compose(self, data):
		data[0:4] = len(self.toc_values).to_bytes(4, BO_LE)
		offset = 4+(8*len(self.toc_values))
		for i in range(0, len(self.toc_values)):
			size = 4+(len(self.toc_values[i])*self.ENS)
			x = 4+(8*i)
			data[x:x+4] = offset.to_bytes(4, BO_LE)
			data[x+4:x+8] = size.to_bytes(4, BO_LE)
			data[offset:offset+4] = (i+1).to_bytes(4, BO_LE)
			for j in range(0, len(self.toc_values[i])):
				x = offset+4+(self.ENS*j)
				data[x:x+self.ENS] = bytes(self.toc_values[i][j].ljust(self.ENS), CHARSET)
			offset += size

	def add_entry(self, name, desc):
		self.toc_values[0].append(name)
		self.toc_values[1].append(desc)

	def del_entry(self, index):
		del self.toc_values[0][index]
		del self.toc_values[1][index]

	def __str__(self):
		fmt = """
CRP08 TOC Chunk:

	Names : {:s}
	Desc. : {:s}
"""
		return fmt.format(
			" ".join(self.toc_values[0]),
			" ".join(self.toc_values[1])
		)

# Data as interpreted after decryption by a T4e/T6 ECU.
#
# Data ECU format:
#
#  12 Bytes    - Encryption header
#  64 Bytes    - ECU header
#   x Bytes    - Data to be flashed
#   x Bytes    - XTEA padding
#
# Encryption header format:
#
#   8 Bytes    - XTEA Salt or Initialization Vector (Random values)
#   4 Bytes BE - XTEA Size of data before padding
#
# ECU header format:
#
#  32 Bytes    - Identification string, like "T4E" padded with spaces
#   4 Bytes BE - Destination address
#   4 Bytes BE - Data size
#   4 Bytes BE - Max version of the bootloader to accept the file
#   4 Bytes BE - Min version of the bootloader to accept the file
#  16 Bytes    - Filled with 0x00
#
# Valid addresses for a T4E are:
#
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
# Valid addresses for a T6 are:
#
#  Flash:
#   0x1 (0x000800)
#   0x2 (0x000808) - Payload 4 Bytes (0xFFFFFFFF (Accept unencrypted) -> 0x1 Only CRP)
#   0x3 (0x000838) - Payload 32 Bytes
#   0x4 (0x040000) - Payload max. size 0xC0000 (prog)
#   0x5 (0x020000) - Payload max. size 0x10000 (calrom)
#   0x6 (0x030000) - Payload max. size 0x10000 (not always available)
#   0x7 (0x01C000) - Payload 32 Bytes
#   0x8 (0x01C000) - Payload 32 Bytes
#   0x9 (0x01C020) - Payload 32 Bytes
#   0xA (0x000858) - Payload 32 Bytes
#   0xB (0x000878) - Payload 32 Bytes
#
# Addresses in the T6 are reference number and not *real* addresses.
#
class CRP08_data_ecu(BinData):
	def __init__(self, key):
		self.xtea = CRP08_xtea(key)

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
		self.xtea.decrypt_cbc(data, plain)

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
			raise CRP08_exception("Size mismatch!")

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
		self.xtea.encrypt_cbc(plain, data)

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

# The following chunks of a CRP data contains data to flash through CAN-Bus.
#
# Chunk CAN format:
#
#   4 Bytes LE - Sould always be 0x0001010A for EMS and 0x0002010C for TCU
#   4 Bytes LE - CAN Bitrate
#   4 Bytes LE - CAN Remote ID 1
#   4 Bytes LE - CAN Local ID 1
#   4 Bytes LE - CAN Remote ID 2
#   4 Bytes LE - CAN Local ID 2
#  40 Bytes    - Filled with 0x00
#   x Bytes    - XTEA Encrypted data (see Data ECU format)
#
class CRP08_chunk_can(BinData):
	SIGNATURE_EMS = 0x0001010A # EMS
	SIGNATURE_TCU = 0x0002010C # TCU

	def __init__(self, key):
		# Configuration header (64 Bytes)
		self.signature = self.SIGNATURE_EMS
		self.can_bitrate = 500
		self.can_remote_id1 = 0x50
		self.can_local_id1 = 0x7A0
		self.can_remote_id2 = 0x51
		self.can_local_id2 = 0x7A1

		# Encrypted data
		self.is_encrypted = (key == None)
		if(self.is_encrypted): self.data = None
		else: self.data = CRP08_data_ecu(key)

	def setTCUaddr(self):
		self.signature = self.SIGNATURE_TCU
		self.can_remote_id1 = 0x60
		self.can_local_id1 = 0x7B0
		self.can_remote_id2 = 0x52
		self.can_local_id2 = 0x7A2

	def parse(self, data):
		# Configuration header (64 Bytes)
		self.signature = int.from_bytes(data[0:4], BO_LE)
		self.can_bitrate = int.from_bytes(data[4:8], BO_LE)
		self.can_remote_id1 = int.from_bytes(data[8:12], BO_LE)
		self.can_local_id1 = int.from_bytes(data[12:16], BO_LE)
		self.can_remote_id2 = int.from_bytes(data[16:20], BO_LE)
		self.can_local_id2 = int.from_bytes(data[20:24], BO_LE)

		# TODO: T6 CRP have a value in data[60:64]... A CRC for the data?

		# Encrypted data
		if(self.is_encrypted): self.data = data[64:]
		else: self.data.parse(data[64:])

	def get_size(self):
		if(self.is_encrypted): return 64 + len(self.enc_data)
		else: return 64 + self.data.get_size()

	def compose(self, data):
		# Configuration header (64 Bytes)
		data[0:4] = self.signature.to_bytes(4, BO_LE)
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

	Signature : 0x{:8X}
	Bitrate   : {:d} kbits/s
	Remote ID : 0x{:3X} / 0x{:3X}
	Local ID  : 0x{:3X} / 0x{:3X}
"""
		return fmt.format(
			self.signature,
			self.can_bitrate,
			self.can_remote_id1, self.can_remote_id2,
			self.can_local_id1, self.can_local_id2
		) + ("" if(self.is_encrypted) else str(self.data))

# CRP 08 format:
#
#   4 Bytes LE - Number of chunks
#   x Bytes    - Multiple "Chunk offset and size"
#   x Bytes    - All chunks
#   2 Bytes LE - Checksum
#
# Chunk offset and size format:
#
#   4 Bytes LE - Offset of the chunk
#   4 Bytes LE - Size of the chunk
#
class CRP08(BinData):
	variants = [
		["T4E",CRP08_xtea.T4E_KEY,"T4E",0x10000,0x20000,False,"LOTUS_T4E"],
		["T6",CRP08_xtea.T6_KEY,"ECU T6",0x5,0x4,False,"LOTUS_T6"],
		["T6 Caterham",CRP08_xtea.T6_CATERHAM_KEY,"CATERHAM T6",0x5,0x4,False,"CATERHAM_ECU_DURATEC"],
		["CT1 Caterham",CRP08_xtea.T6_CATERHAM_KEY,"CATERHAM CT1",0x5,0x4,False,"CATERHAM_ECU_SIGMA"],
		["TCU",CRP08_xtea.T6_KEY,"TCU MMT/AT REVC",0x5,0x4,True,"LOTUS_TCU"],
		["T6 Yaris",CRP08_xtea.T6_YARIS_KEY,"ECU T6B",0x5,0x4,False,"LOTUS_YARIS"]
	]

	def __init__(self):
		# An empty CRP file
		self.chunks = [CRP08_chunk_toc()]

	def parse(self, data, key):
		# Check the sum
		cksum = sum(data[:-2]) & 0xFFFF
		if(cksum != int.from_bytes(data[-2:], BO_LE)):
			raise CRP08_exception("Wrong sum!")

		# Parse the chunks
		self.chunks = [None] * int.from_bytes(data[0:4], BO_LE)
		for i in range(0, len(self.chunks)):
			x = 4+(8*i)
			offset = int.from_bytes(data[x:x+4], BO_LE)
			size = int.from_bytes(data[x+4:x+8], BO_LE)
			if(i == 0): chunk = CRP08_chunk_toc()
			else: chunk = CRP08_chunk_can(key)
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

	# Create a chunk for the Calibration
	def add_cal(self, file, i=0):
		v = CRP08.variants[i]
		chk = CRP08_chunk_can(v[1])
		chk.data.ecu_id = v[2]
		chk.data.ecu_addr = v[3]
		if(v[5]): chk.setTCUaddr()
		chk.data.import_bin(file)
		self.add_chunk(chk, os.path.basename(file), v[6])

	# Create a chunk for the Program
	def add_prog(self, file, i=0):
		v = CRP08.variants[i]
		chk = CRP08_chunk_can(v[1])
		chk.data.ecu_id = v[2]
		chk.data.ecu_addr = v[4]
		if(v[5]): chk.setTCUaddr()
		chk.data.import_bin(file)
		self.add_chunk(chk, os.path.basename(file), v[6])

	# Unpack multiple chunks from a CRP file.
	def read_file(self, file, i=0):
		key = None if (i == None) else CRP08.variants[i][1]
		with open(file, 'rb') as f:
			self.parse(memoryview(f.read()), key)

	# Pack multiple chunks into a CRP file.
	def write_file(self, file):
		data = memoryview(bytearray(self.get_size()))
		self.compose(data)
		with open(file, 'wb') as f: f.write(data)

	def __str__(self):
		return "".join([str(c) for c in self.chunks])

if __name__ == "__main__":
	print("BIN to CRP file tool for Lotus T4e/T6 ECU\n")
	if(len(sys.argv) >= 2):
		i = {"T4e": 0, "T6": 1, "CAT": 2, "TCU": 3}[sys.argv[1]]
		crp = CRP08()
	if  (len(sys.argv) >= 5 and sys.argv[2] == "calrom"):
		print(f"-- Add {sys.argv[3]} into {sys.argv[4]} --")
		crp.add_cal(sys.argv[3], i)
		print(crp.chunks[1])
		crp.write_file(sys.argv[4])
	elif(len(sys.argv) >= 5 and sys.argv[2] == "prog"):
		print(f"-- Add {sys.argv[3]} into {sys.argv[4]} --")
		crp.add_prog(sys.argv[3], i)
		print(crp.chunks[1])
		crp.write_file(sys.argv[4])
	elif(len(sys.argv) >= 6 and sys.argv[2] == "both"):
		print(f"-- Add {sys.argv[3]} into {sys.argv[5]} --")
		crp.add_cal(sys.argv[3], i)
		print(crp.chunks[1])
		print(f"-- Add {sys.argv[4]} into {sys.argv[5]} --")
		crp.add_prog(sys.argv[4], i)
		print(crp.chunks[2])
		crp.write_file(sys.argv[5])
	elif(len(sys.argv) >= 4 and sys.argv[2] == "unpack"):
		crp.read_file(sys.argv[3], i)
		for i in range(1, len(crp.chunks)):
			bin_file = crp.chunks[0].toc_values[0][i-1]
			print(f"-- [CHUNK {i:d}] Extract {bin_file} from {sys.argv[3]} --")
			crp.chunks[i].data.export_bin(bin_file)
			print(crp.chunks[i])
	else:
		prog = os.path.basename(sys.argv[0])
		print("usage:")
		print(f"\t{prog} [T4e|T6|CAT|TCU] calrom BIN_FILE CRP_FILE")
		print(f"\t{prog} [T4e|T6|CAT|TCU] prog BIN_FILE CRP_FILE")
		print(f"\t{prog} [T4e|T6|CAT|TCU] both CALROM_BIN_FILE PROG_BIN_FILE CRP_FILE")
		print(f"\t{prog} [T4e|T6|CAT|TCU] unpack CRP_FILE")

