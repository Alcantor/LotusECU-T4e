# Very interesting:
# http://www.danielvik.com/2013/07/rewinding-crc-calculating-crc-backwards.html

import os

class CRC:
	def __init__(self, initvalue):
		self.table = [0] * 256
		# Table reverse contains only one solution.
		# TODO: Make table_reverse a 2D array to contain all solutions.
		self.table_reverse = [0] * 256
		self.set_initvalue(initvalue)
		self.reset()
	def set_initvalue(self, initvalue):
		self.initvalue = initvalue
	def reset(self):
		self.crc = self.initvalue
	def update(self, data):
		for byte in data: self.update_byte(byte)
	def update_reverse(self, data):
		for byte in reversed(data): self.update_byte_reverse(byte)
	def get(self):
		return self.crc
	def do_file(self, filename):
		with open(filename, 'rb') as f:
			self.reset()
			while(True):
				chunk = f.read(1024)
				if(len(chunk) == 0): break
				self.update(chunk)

class CRC8Normal(CRC):
	def __init__(self, polynomial, initvalue=0xFF):
		super().__init__(initvalue)
		# Forward table
		for i in range(0,256):
			c = i
			for j in range(0,8):
				c = polynomial ^ (c << 1) if (c & 0x80) else c << 1
			self.table[i] = c & 0xFF;
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i]] = i
	def update_byte(self, byte):
		self.crc = self.table[self.crc ^ byte]
	def update_byte_reverse(self, byte):
		self.crc = self.table_reverse[self.crc] ^ byte

class CRC8Reflect(CRC):
	def __init__(self, polynomial, initvalue=0xFF):
		super().__init__(initvalue)
		invertPolynomial = CRC8Reflect.reflect(polynomial)
		# Forward table
		for i in range(0,256):
			c = i
			for j in range(0,8):
				c = invertPolynomial ^ (c >> 1) if (c & 0x01) else c >> 1
			self.table[i] = c;
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i]] = i
	def update_byte(self, byte):
		self.crc = self.table[self.crc ^ byte]
	def update_byte_reverse(self, byte):
		self.crc = self.table_reverse[self.crc] ^ byte
	def reflect(p):
		p = ((p & 0x55) << 1) | ((p >> 1) & 0x55)
		p = ((p & 0x33) << 2) | ((p >> 2) & 0x33)
		p = (p << 4) | (p >> 4)
		return p & 0xFF

class CRC16Normal(CRC):
	def __init__(self, polynomial, initvalue=0xFFFF):
		super().__init__(initvalue)
		# Forward table
		for i in range(0,256):
			c = i << 8
			for j in range(0,8):
				c = polynomial ^ (c << 1) if (c & 0x8000) else c << 1
			self.table[i] = c & 0xFFFF
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i] & 0xFF] = i
	def update_byte(self, byte):
		self.crc = self.table[(self.crc >> 8) ^ byte] ^ (self.crc << 8)
		self.crc &= 0xFFFF
	def update_byte_reverse(self, byte):
		i = self.table_reverse[self.crc & 0xFF]
		self.crc = ((i ^ byte) << 8) | ((self.table[i] ^ self.crc) >> 8)

class CRC16Reflect(CRC):
	def __init__(self, polynomial, initvalue=0xFFFF):
		super().__init__(initvalue)
		invertPolynomial = CRC16Reflect.reflect(polynomial)
		# Forward table
		for i in range(0,256):
			c = i
			for j in range(0,8):
				c = invertPolynomial ^ (c >> 1) if (c & 0x0001) else c >> 1
			self.table[i] = c
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i] >> 8] = i
	def update_byte(self, byte):
		self.crc = self.table[(self.crc & 0xFF) ^ byte] ^ (self.crc >> 8)
	def update_byte_reverse(self, byte):
		i = self.table_reverse[self.crc >> 8]
		self.crc = (i ^ byte) | ((self.table[i] ^ self.crc) << 8)
		self.crc &= 0xFFFF
	def reflect(p):
		p = ((p & 0x5555) << 1) | ((p >> 1) & 0x5555)
		p = ((p & 0x3333) << 2) | ((p >> 2) & 0x3333)
		p = ((p & 0x0F0F) << 4) | ((p >> 4) & 0x0F0F)
		p = (p << 8) | (p >> 8)
		return p & 0xFFFF

class CRC32Normal(CRC):
	def __init__(self, polynomial, initvalue=0xFFFFFFFF):
		super().__init__(initvalue)
		# Forward table
		for i in range(0,256):
			c = i << 24
			for j in range(0,8):
				c = polynomial ^ (c << 1) if (c & 0x80000000) else c << 1
			self.table[i] = c & 0xFFFFFFFF
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i] & 0xFF] = i
	def update_byte(self, byte):
		self.crc = self.table[(self.crc >> 24) ^ byte] ^ (self.crc << 8)
		self.crc &= 0xFFFFFFFF
	def update_byte_reverse(self, byte):
		i = self.table_reverse[self.crc & 0xFF]
		self.crc = ((i ^ byte) << 24) | ((self.table[i] ^ self.crc) >> 8)

class CRC32Reflect(CRC):
	def __init__(self, polynomial, initvalue=0xFFFFFFFF):
		super().__init__(initvalue)
		invertPolynomial = CRC32Reflect.reflect(polynomial)
		# Forward table
		for i in range(0,256):
			c = i
			for j in range(0,8):
				c = invertPolynomial ^ (c >> 1) if (c & 0x00000001) else c >> 1
			self.table[i] = c
		# Backward table
		for i in range(0,256):
			self.table_reverse[self.table[i] >> 24] = i
	def update_byte(self, byte):
		self.crc = self.table[(self.crc & 0xFF) ^ byte] ^ (self.crc >> 8)
	def update_byte_reverse(self, byte):
		i = self.table_reverse[self.crc >> 24]
		self.crc = (i ^ byte) | ((self.table[i] ^ self.crc) << 8)
		self.crc &= 0xFFFFFFFF
	def reflect(p):
		p = ((p & 0x55555555) << 1) | ((p >> 1) & 0x55555555)
		p = ((p & 0x33333333) << 2) | ((p >> 2) & 0x33333333)
		p = ((p & 0x0F0F0F0F) << 4) | ((p >> 4) & 0x0F0F0F0F)
		p = ((p & 0x00FF00FF) << 8) | ((p >> 8) & 0x00FF00FF)
		p = (p << 16) | (p >> 16)
		return p & 0xFFFFFFFF

if __name__ == "__main__":
	print("Heavy duty CRC library... Make some tests:\n")
	data = b"The quick brown fox jumps over the lazy dog"

	# Test CRC-8/CDMA2000
	crc = CRC8Normal(0x9B, initvalue=0xFF)
	crc.update(data)
	if(crc.get() == 0x02): print("CRC-8/CDMA2000 is OK")
	crc.update_reverse(data)
	if(crc.get() == 0xFF): print("Reverse CRC-8/CDMA2000 is OK")

	# Test CRC-8/DARC
	crc = CRC8Reflect(0x39, initvalue=0x00)
	crc.update(data)
	if(crc.get() == 0xA1): print("CRC-8/DARC is OK")
	crc.update_reverse(data)
	if(crc.get() == 0x00): print("Reverse CRC-8/DARC is OK")

	# Test CRC-16/CCITT-FALSE
	crc = CRC16Normal(0x1021, initvalue=0xFFFF)
	crc.update(data)
	if(crc.get() == 0x8FDD): print("CRC-16/CCITT-FALSE is OK")
	crc.update_reverse(data)
	if(crc.get() == 0xFFFF): print("Reverse CRC-16/CCITT-FALSE is OK")

	# Test CRC-16/KERMIT
	crc = CRC16Reflect(0x1021, initvalue=0x0000)
	crc.update(data)
	if(crc.get() == 0xC459): print("CRC-16/KERMIT is OK")
	crc.update_reverse(data)
	if(crc.get() == 0x0000): print("Reverse CRC-16/KERMIT is OK")

	# Test CRC-32/MPEG-2
	crc = CRC32Normal(0x04C11DB7, initvalue=0xFFFFFFFF)
	crc.update(data)
	if(crc.get() == 0xBA62119E): print("CRC-32/MPEG-2 is OK")
	crc.update_reverse(data)
	if(crc.get() == 0xFFFFFFFF): print("Reverse CRC-32/MPEG-2 is OK")

	# Test CRC-32C
	crc = CRC32Reflect(0x1EDC6F41, initvalue=0xFFFFFFFF)
	crc.update(data)
	if(crc.get() ^ 0xFFFFFFFF == 0x22620404): print("CRC-32C is OK")
	crc.update_reverse(data)
	if(crc.get() == 0xFFFFFFFF): print("Reverse CRC-32C is OK")

