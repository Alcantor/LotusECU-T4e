#!/usr/bin/python3

import os

class FileProgressException(Exception):
	pass

class FileProgress:
	# Override it if needed
	def log(self, msg):
		print(msg)

	# Override it if needed
	def progress(self):
		print(".", end="", flush=True)

	# Override it if needed
	def progress_end(self):
		print()
		
	def __aligned(self, size, chunk_size, chunk_align):
		if(size % chunk_size != 0 and chunk_align):
			raise FileProgressException("File size is not a multiple of "+str(chunk_size))

	def download(self, address, size, filename, read_fnct, chunk_size, chunk_align):
		self.log("Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
		self.__aligned(size, chunk_size, chunk_align)
		with open(filename,'wb') as f:
			while(size > 0):
				if(chunk_align):
					chunk = read_fnct(address)
				else:
					chunk_size = min(chunk_size, size)
					chunk = read_fnct(address, chunk_size)
				f.write(chunk)
				self.progress()
				address += chunk_size
				size -= chunk_size
			self.progress_end()

	def verify(self, address, filename, read_fnct, chunk_size, chunk_align, offset=0, size=None):
		if(not size): size = os.path.getsize(filename) - offset
		self.log("Verify "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		self.__aligned(size, chunk_size, chunk_align)
		with open(filename,'rb') as f:
			f.seek(offset)
			while(size > 0):
				if(chunk_align):
					chunk = read_fnct(address)
				else:
					chunk_size = min(chunk_size, size)
					chunk = read_fnct(address, chunk_size)
				f_chunk = f.read(chunk_size)
				if(f_chunk != chunk):
					raise FileProgressException("Verify failed! @ "+hex(address))
				self.progress()
				address += chunk_size
				size -= chunk_size
			self.progress_end()

	def verify_blank(self, address, size, read_fnct, chunk_size, chunk_align):
		self.log("Verify Blank "+str(size)+" bytes @ "+hex(address))
		self.__aligned(size, chunk_size, chunk_align)
		while(size > 0):
			if(chunk_align):
				chunk = read_fnct(address)
			else:
				chunk_size = min(chunk_size, size)
				chunk = read_fnct(address, chunk_size)
			for byte in chunk:
				if(byte != 0xFF):
					raise FileProgressException("Verify Blank failed! @ "+hex(address))
			self.progress()
			address += chunk_size
			size -= chunk_size
		self.progress_end()

	def upload(self, address, filename, write_fnct, chunk_size, chunk_align, offset=0, size=None):
		if(not size): size = os.path.getsize(filename) - offset
		self.log("Upload "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		self.__aligned(size, chunk_size, chunk_align)
		with open(filename,'rb') as f:
			f.seek(offset)
			while(size > 0):
				chunk = f.read(chunk_size)
				chunk_size = len(chunk)
				write_fnct(address, chunk)
				self.progress()
				address += chunk_size
				size -= chunk_size
			self.progress_end()

if __name__ == "__main__":
	print("Library to upload/download/verify files.")

