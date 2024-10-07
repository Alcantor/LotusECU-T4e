import os, sys, datetime, string
from lib.crc import CRC16Reflect
from lib.ppc32 import PPC32

# Some constants
BO_LE = 'little'
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

# Calibration (calrom.bin) Format:
#
#    32 Bytes   - Description
# 15502 Bytes   - Tables
#     4 Bytes   - "WTF?" to unlock
#     2 Bytes   - 16 Bits CRC
#
class Calibration():
	offsets = [
		# Name        , size  , strt, end   , crc   , unlock
		["T4e white 1", 0x3C8E, 0x00, 0x3C8E, None  , None  ],
		["T4e white 2", 0x3C94, 0x20, 0x3C92, 0x3C92, 0x3C8E],
		["T4e white 3", 0x3C9C, 0x20, 0x3C92, 0x3C92, 0x3C8E],
		["T4e white 4", 0x3CA0, 0x00, 0x3C8E, None  , None  ],
		["T4e white 5", 0x3CB4, 0x20, 0x3C92, 0x3C92, 0x3C8E],
		["T4e black 1", 0x3CB4, 0x20, 0x3CB2, 0x3CB2, 0x3CAE],
		["T4e black 2", 0x3CC4, 0x20, 0x3CC2, 0x3CC2, 0x3CAE],
		["T6 V6 3"    , 0x4874, 0x20, 0x4872, 0x4872, 0x486E],
		["T6 V6 1"    , 0x61DA, 0x20, 0x61D8, 0x61D8, 0x61D4],
		["T6 L4"      , 0x69A8, 0x20, 0x69A6, 0x69A6, 0x69A2],
		["T6 V6 2"    , 0x69AC, 0x20, 0x69AA, 0x69AA, 0x69A6]
		# Keep size in ascending order for better detection.
		# All variants since 08 should be covered. Pre-08 is the jungle!
	]

	LOCK_MAGIC1 = b'\x00\x00\x00\x00'
	LOCK_MAGIC2 = b'    ' # Sometimes 4 spaces are used to lock an ECU.
	UNLOCK_MAGIC = bytes("WTF?", CHARSET)
	# UNLOCK_MAGIC = bytes("C1D3", CHARSET) # Caterham C1D3M000
	# UNLOCK_MAGIC = bytes("D1S1", CHARSET) # Caterham D1S17000

	def __init__(self):
		self.data = memoryview(bytearray(0xFFFF))
		self.map(0)
		self.set_desc("Empty Cal.")

	def read_file(self, file):
		with open(file, 'rb') as f:
			self.data = memoryview(bytearray(f.read()))

	def write_file(self, file):
		with open(file, 'wb') as f: f.write(self.data)

	def resize_file(self, newsize):
		if(newsize <= len(self.data)):
			self.data = memoryview(self.data[0:newsize])
		else:
			newbuffer = bytearray(newsize)
			newbuffer[0:len(self.data)] = self.data;
			for i in range(len(self.data), newsize):
				newbuffer[i] = 0xFF
			self.data = memoryview(newbuffer)

	def map(self, i):
		o = Calibration.offsets[i]
		self.name = o[0]
		self.size = o[1]
		self.free = self.data[o[1]:]
		self.desc = self.data[0:32]
		self.crc_data = self.data[o[2]:o[3]]
		if(o[4] != None): self.crc = self.data[o[4]:o[4]+2]
		else: self.crc = None
		if(o[5] != None): self.magic = self.data[o[5]:o[5]+4]
		else: self.magic = None

	def detect(self):
		blank = b'\xFF\xFF\xFF\xFF'
		for i in range(0, len(Calibration.offsets)):
			self.map(i)
			if(len(self.data) >= self.size and (len(self.free) == 0
					or self.free[0:4] == blank) and self.magic in [
						None,
						Calibration.LOCK_MAGIC1,
						Calibration.LOCK_MAGIC2,
						Calibration.UNLOCK_MAGIC
					]):
				return i
		raise Exception("Unknow variant!")

	def get_desc(self):
		return str(self.desc, CHARSET).rstrip()

	def set_desc(self, desc):
		self.desc[:] = bytes(desc.ljust(32), CHARSET)

	def get_generic_vin(self):
		return str(self.crc_data[-22:-5], CHARSET).rstrip()

	def search_crc_cmpli(self, prog_file):
		opcode = PPC32.ppc_cmpli(0, self.compute_crc())
		offset = 0
		with open(prog_file, 'rb') as fprg:
			while(True):
				chunk = fprg.read(4)
				chunk_size = len(chunk)
				if(chunk_size != 4): break # EOF
				if(chunk == opcode): return offset
				offset += chunk_size
		return None

	def match_crc(self, desc, crc):
		if(self.desc != self.crc_data[:32]):
			raise Exception("The signature is not in CRC data.")
		# Compute CRC backward
		crc = CRC16Reflect(0x8005, initvalue=crc)
		crc.update_reverse(self.crc_data[32:])
		crc_desc = crc.get() # The first 32 bytes should match this CRC
		# Compute CRC forward
		crc.set_initvalue(0x0000)
		date = datetime.datetime.now()
		onesecond = datetime.timedelta(seconds=1)
		while(True):
			crc.reset()
			self.set_desc(desc+date.strftime("%m-%d-%Y %H:%M:%S"))
			crc.update(self.desc)
			if(crc.get() == crc_desc): break
			date -= onesecond

	def match_crc2(self, crc):
		if(self.crc_data[-22:-19] != b"SCC"):
			raise Exception("The generic VIN is not found.")
		# Compute CRC backward
		crc = CRC16Reflect(0x8005, initvalue=crc)
		crc.update_reverse(self.crc_data[-5:])
		crc_partial = crc.get()
		# Compute CRC forward
		crc.set_initvalue(0x0000)
		crc.reset()
		crc.update(self.crc_data[:-9])
		crc.set_initvalue(crc.get())
		# Search a VIN that satisfied the CRC using printable characters
		c = bytes(string.digits+string.ascii_letters, CHARSET)
		ca = [len(c)**x for x in reversed(range(0,4))]
		max = len(c)**4
		i = 0
		while(True):
			crc.reset()
			data = bytes([c[i//x%len(c)] for x in ca])
			crc.update(data)
			if(crc.get() == crc_partial): break
			if(i >= max): raise Exception("Unpossible!")
			i += 1
		# Update
		self.crc_data[-9:-5] = data

	def get_crc(self):
		return int.from_bytes(self.crc, BO_BE)

	def set_crc(self, crc):
		self.crc[:] = crc.to_bytes(2, BO_BE)

	def compute_crc(self):
		crc = CRC16Reflect(0x8005, initvalue=0x0000)
		crc.update(self.crc_data)
		return crc.get()

	def is_unlocked(self):
		return self.magic == self.UNLOCK_MAGIC

	def lock(self):
		self.magic[:] = self.LOCK_MAGIC1

	def unlock(self):
		self.magic[:] = self.UNLOCK_MAGIC

	def __str__(self):
		if(self.magic != None):
			text_unlock = ("Yes" if(self.is_unlocked()) else "No")
		else:
			text_unlock = "N/A"
		if(self.crc != None):
			text_crc = "0x{:04X}".format(self.get_crc())
		else:
			text_crc = "N/A"
		fmt = """
{:s}:

	Description : {:s}
	Size        : {:d} bytes
	Unlocked    : {:s}
	CRC         : 0x{:04X}
	CRC stored  : {:s}
	File size   : {:d} bytes
"""
		return fmt.format(
			self.name,
			self.get_desc(),
			self.size,
			text_unlock,
			self.compute_crc(),
			text_crc,
			len(self.data)
		)

#def check_eeprom(eeprom_file, size=0x53C):
#	crc = CRC16Reflect(0x8005, initvalue=0x0000) # CRC for EEPROM
#	size_crc = 4
#	with open(eeprom_file, 'rb') as feeprom:
#		crc.update(feeprom.read(size-size_crc))
#		print("EEPROM CRC: "+hex(crc.get()))
#		crc2 = int.from_bytes(feeprom.read(size_crc), "big")
#		print("Should be CRC: "+hex(crc2))
#		if(crc.get() == crc2):
#			print("CRC is correct!")
#		else:
#			print("CRC is wrong!")

if __name__ == "__main__":
	print("CRC tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 6 and sys.argv[1] == "sign"):
		cal1 = Calibration()
		cal1.read_file(sys.argv[2])
		cal1.detect()
		cal2 = Calibration()
		cal2.read_file(sys.argv[3])
		cal2.detect()
		cal2.match_crc(sys.argv[5]+" ", cal1.compute_crc())
		cal2.write_file(sys.argv[4])
		print(cal2)
		print("--> THIS IS A FAKE DATE TO MATCH THE ORIGINAL CRC")
	elif(len(sys.argv) >= 4 and sys.argv[1] == "search"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		cal.detect()
		offset = cal.search_crc_cmpli(sys.argv[3])
		if(offset == None): print("CRC cmplwi not found!")
		else: print(f"CRC cmplwi offset: 0x{offset:06X}")
	elif(len(sys.argv) >= 3 and sys.argv[1] == "check"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		cal.detect()
		print(cal)
	elif(len(sys.argv) >= 4 and sys.argv[1] == "unlock"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		cal.detect()
		cal.unlock()
		cal.set_crc(cal.compute_crc())
		cal.write_file(sys.argv[3])
		print(cal)
	#elif(len(sys.argv) >= 3 and sys.argv[1] == "check_eeprom"):
	#	print("White:\n")
	#	check_eeprom(sys.argv[2])
	#	print("\nBlack:\n")
	#	check_eeprom(sys.argv[2], 0x56C)
	else:
		prog = os.path.basename(sys.argv[0])
		print("usage:")
		print(f"\t{prog} sign ORIGINAL_CALROM MODIFIED_CALROM OUTFILE SIGNATURE")
		print(f"\t{prog} search_prog ORIGINAL_CALROM ORIGINAL_PROG")
		print(f"\t{prog} check ORIGINAL_CALROM")
		print(f"\t{prog} unlock CALROM OUTFILE")
		#print("\t"+prog+" check_eeprom EEPROM")

