import os, sys, datetime
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
	def __init__(self):
		self.data = bytearray(27050)
		self.set_desc("Empty Cal.")

	def get_desc(self):
		return str(bytes(self.data[0:32]), CHARSET).rstrip()

	def set_desc(self, desc):
		self.data[0:32] = bytes(desc.ljust(32), CHARSET)

	def get_size(self):
		return len(self.data)

	def read_file(self, file):
		with open(file, 'rb') as f:
			# TODO: If CRC ends with 0xFF? Not a good idea to rstrip...
			self.data = memoryview(bytearray(f.read().rstrip(b'\xFF')))

	def write_file(self, file):
		with open(file, 'wb') as f: f.write(self.data)

	# For white calibration ################################################
	def wh_search_crc_cmpli(self, prog_file):
		opcode = PPC32.ppc_cmpli(0, self.wh_compute_crc())
		offset = 0
		with open(prog_file, 'rb') as fprg:
			while(True):
				chunk = fprg.read(4)
				chunk_size = len(chunk)
				if(chunk_size != 4): break # EOF
				if(chunk == opcode): return offset
				offset += chunk_size
		return -1

	def wh_modify_crc(self, desc, crc):
		# Compute CRC backward
		crc = CRC16Reflect(0x8005, initvalue=crc)
		crc.update_reverse(self.data[32:15502])
		crc_desc = crc.get() # The first 32 bytes should match this CRC
		crc.set_initvalue(0x0000)
		# Compute CRC forward		
		date = datetime.datetime.now()
		onesecond = datetime.timedelta(seconds=1)
		while(True):
			crc.reset()
			self.set_desc(desc+date.strftime("%m-%d-%Y %H:%M:%S"))
			crc.update(self.data[0:32])
			if(crc.get() == crc_desc): break
			date -= onesecond

	def wh_compute_crc(self):
		crc = CRC16Reflect(0x8005, initvalue=0x0000)
		crc.update(self.data[0:15502])
		return crc.get()

	# For black calibration ################################################
	LOCK_MAGIC = b'\x00\x00\x00\x00'
	UNLOCK_MAGIC = bytes("WTF?", CHARSET)

	def bl_is_unlocked(self):
		return self.data[15534:15538] == self.UNLOCK_MAGIC

	def bl_lock(self):
		self.data[15534:15538] = self.LOCK_MAGIC

	def bl_unlock(self):
		self.data[15534:15538] = self.UNLOCK_MAGIC

	def bl_get_crc(self):
		return int.from_bytes(self.data[15538:15540], BO_BE)

	def bl_set_crc(self, crc):
		self.data[15538:15540] = crc.to_bytes(2, BO_BE)

	def bl_compute_crc(self):
		crc = CRC16Reflect(0x8005, initvalue=0x0000)
		crc.update(self.data[32:15538])
		return crc.get()

	# For t6 calibration ################################################
	def t6_is_unlocked(self):
		return self.data[26962:26966] == self.UNLOCK_MAGIC

	def t6_lock(self):
		self.data[26962:26966] = self.LOCK_MAGIC

	def t6_unlock(self):
		self.data[26962:26966] = self.UNLOCK_MAGIC

	def t6_get_crc(self):
		return int.from_bytes(self.data[27046:27050], BO_BE)

	def t6_set_crc(self, crc):
		self.data[27046:27050] = crc.to_bytes(2, BO_BE)

	def t6_compute_crc(self):
		crc = CRC16Reflect(0x8005, initvalue=0x0000)
		crc.update(self.data[32:27046])
		return crc.get()

	def __str__(self):
		fmt = """
Calibration File:

	Description : {:s}
	Size        : {:d} bytes

T4e White:

	CRC         : 0x{:04X}

T4e Black:

	Unlocked    : {:s}
	CRC         : 0x{:04X}
	CRC stored  : 0x{:04X}

T6 Black:

	Unlocked    : {:s}
	CRC         : 0x{:04X}
	CRC stored  : 0x{:04X}
"""
		return fmt.format(
			self.get_desc(),
			self.get_size(),
			self.wh_compute_crc(),
			("Yes" if(self.bl_is_unlocked()) else "No"),
			self.bl_compute_crc(),
			self.bl_get_crc(),
			("Yes" if(self.t6_is_unlocked()) else "No"),
			self.t6_compute_crc(),
			self.t6_get_crc()
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
	if  (len(sys.argv) >= 6 and sys.argv[1] == "sign_calrom"):
		cal1 = Calibration()
		cal1.read_file(sys.argv[2])
		cal2 = Calibration()
		cal2.read_file(sys.argv[3])
		cal2.wh_modify_crc(sys.argv[5]+" ", cal1.wh_compute_crc())
		cal2.write_file(sys.argv[4])
		print(cal2)
		print("--> THIS IS A FAKE DATE TO MATCH THE ORIGINAL CRC")
	elif(len(sys.argv) >= 4 and sys.argv[1] == "search_crc_prog"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		offset = cal.wh_search_crc_cmpli(sys.argv[3])
		if(offset < 0): print("CRC cmplwi not found!")
		else: print("CRC cmplwi offset: "+hex(offset))
	elif(len(sys.argv) >= 3 and sys.argv[1] == "check_crc_black_calrom"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		print(cal)
	elif(len(sys.argv) >= 4 and sys.argv[1] == "unlock_black_calrom"):
		cal = Calibration()
		cal.read_file(sys.argv[2])
		cal.bl_unlock()
		cal.bl_set_crc(cal.bl_compute_crc())
		cal.write_file(sys.argv[3])
		print(cal)
	#elif(len(sys.argv) >= 3 and sys.argv[1] == "check_crc_eeprom"):
	#	print("White:\n")
	#	check_eeprom(sys.argv[2])
	#	print("\nBlack:\n")
	#	check_eeprom(sys.argv[2], 0x56C)
	else:
		prog = os.path.basename(sys.argv[0])
		print("usage:")
		print("\t"+prog+" sign_calrom ORIGINAL_CALROM MODIFIED_CALROM OUTFILE SIGNATURE")
		print("\t"+prog+" search_crc_prog ORIGINAL_CALROM ORIGINAL_PROG")
		print("\t"+prog+" check_crc_black_calrom ORIGINAL_CALROM")
		print("\t"+prog+" unlock_black_calrom CALROM OUTFILE")
		#print("\t"+prog+" check_crc_eeprom EEPROM")

