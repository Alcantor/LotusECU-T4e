#!/usr/bin/python3

import os

def ppc_cmplwi_opcode(register, immediate):
	opcode     = bytearray([0x28, 0x00, 0x00, 0x00])
	opcode[1] |= register & 0x1F
	opcode[2] |= (immediate >>  8) & 0xFF
	opcode[3] |= immediate & 0xFF
	return opcode

def crc16_reflect(p):
	p = ((p & 0x5555) << 1) | ((p >> 1) & 0x5555)
	p = ((p & 0x3333) << 2) | ((p >> 2) & 0x3333)
	p = ((p & 0x0F0F) << 4) | ((p >> 4) & 0x0F0F)
	p = (p << 8) | (p >> 8)
	return p & 0xFFFF

class CRC16Normal:
	def __init__(self, polynomial, initvalue=0xFFFF):
		self.table = [0] * 256
		for i in range(0,256):
			c = i << 8
			for j in range(0,8):
				c = polynomial ^ ((c << 1) & 0xFFFF) if (c & 0x8000) else c << 1
			self.table[i] = c;
		self.initvalue = initvalue
		self.reset()
	def reset(self):
		self.crc = self.initvalue
	def update_byte(self, byte):
		#self.crc = (self.table[(self.crc >> 8)] ^ (self.crc << 8) ^ (byte+0xAA)) & 0xFFFF
		self.crc = self.table[(self.crc >> 8) ^ byte] ^ (self.crc << 8) & 0xFFFF
	def update(self, data):
		for byte in data: self.update_byte(byte)
	def get(self):
		return self.crc

class CRC16Reflect:
	def __init__(self, invertPolynomial, initvalue=0xFFFF):
		self.table = [0] * 256
		for i in range(0,256):
			c = i
			for j in range(0,8):
				c = invertPolynomial ^ (c >> 1) if (c & 0x0001) else c >> 1
			self.table[i] = c;
		self.initvalue = initvalue
		self.reset()
	def reset(self):
		self.crc = self.initvalue
	def update_byte(self, byte):
		self.crc = self.table[(self.crc & 0xFF) ^ byte] ^ (self.crc >> 8)
	def update(self, data):
		for byte in data: self.update_byte(byte)
	def get(self):
		return self.crc

def do_bootloader_crc(crcclass, filename):
	size = os.path.getsize(filename)
	print("CRC Bootloader "+str(size)+" bytes from "+filename)
	# The 2 remaining bytes are the CRC itself
	size -= 2
	with open(filename,'rb') as f:
		# Ignore the stage 1 bootloader
		f.seek(0x4000)
		size -= 0x4000
		while(size > 0):
			chunk_size = min(128, size);
			chunk = f.read(chunk_size)
			crcclass.update(chunk)
			size -= chunk_size
		print("The CRC is: "+hex(crcclass.get()))

def do_calrom_crc(crcclass, filename):
	size = 0x3C8E #os.path.getsize(filename)
	print("CRC Calrom "+str(size)+" bytes from "+filename)
	with open(filename,'rb') as f:
		# Ignore the stage 1 bootloader
		while(size > 0):
			chunk_size = min(128, size);
			chunk = f.read(chunk_size)
			crcclass.update(chunk)
			size -= chunk_size
		print("The CRC is: "+hex(crcclass.get()))

def do_decram_crc(crcclass, filename):
	size = 0x538 #os.path.getsize(filename)
	print("CRC Decrom "+str(size)+" bytes from "+filename)
	with open(filename,'rb') as f:
		# Ignore the stage 1 bootloader
		while(size > 0):
			chunk_size = min(128, size);
			chunk = f.read(chunk_size)
			crcclass.update(chunk)
			size -= chunk_size
		print("The CRC is: "+hex(crcclass.get()))

if __name__ == "__main__":	 
	#crc = CRC16Normal(0x1021, initvalue=0x0123) # CRC for bootloader (not working yet), LUT is correct
	crc = CRC16Reflect(crc16_reflect(0x8005), initvalue=0x0000) # CRC for calibration

	#crc.update(b"123456789")
	#print("TEST: "+hex(crc.get()))
	#crc.reset()
	#crc.update(b"123456789")
	#print("TEST: "+hex(crc.get()))
	#crc.reset()
	#print(crc.table)
	#do_bootloader_crc(crc, "ALS3M0244F/bootldr.bin")
	#crc.reset()
	do_calrom_crc(crc, "ALS3M0244F/calrom.bin")
	with open("ALS3M0244F/prog.bin", 'rb') as f:
		offset = f.read().find(ppc_cmplwi_opcode(0, crc.get()))
		print("CRC cmplwi offset in prog.bin: "+hex(offset))
	crc.reset()
	do_calrom_crc(crc, "ALS3M0240J/calrom.bin")
	with open("ALS3M0240J/prog.bin", 'rb') as f:
		offset = f.read().find(ppc_cmplwi_opcode(0, crc.get()))
		print("CRC cmplwi offset in prog.bin: "+hex(offset))
	#crc.reset()
	#do_decram_crc(crc, "ALS3M0244F/decram.bin")

