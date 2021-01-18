#!/usr/bin/python3

import os, sys, argparse, time
import RPi.GPIO as GPIO

# DSCK should be bidirectional
# Put a 5.6kOhm resistor between the ECU and the Raspberry Pi !!!
# DSCK is also pulled down with a 10 kOhm resistor on the ECU

class BDMException(Exception):
	pass

class BDM_PI:
	# Override it if needed
	def log(self, msg):
		print(msg)

	# Override it if needed
	def progress(self):
		print(".", end="", flush=True)

	# Override it if needed
	def progress_end(self):
		print()

	def openGPIO(self, gpio_dsck=4, gpio_dsdi=17, gpio_dsdo=27, hperiod=0):
		self.log("Open GPIO for BDM operation")
		self.gpio_dsck = gpio_dsck
		self.gpio_dsdi = gpio_dsdi
		self.gpio_dsdo = gpio_dsdo
		self.hperiod = hperiod
		GPIO.setwarnings(False)
		GPIO.setmode(GPIO.BCM)
		GPIO.setup(self.gpio_dsck, GPIO.OUT)
		GPIO.setup(self.gpio_dsdi, GPIO.OUT)
		GPIO.setup(self.gpio_dsdo, GPIO.IN)

	def io_byte(self, byte_in):
		byte_out = 0
		for i in reversed(range(0, 8)):
			# Put the bit at the falling edge of clock
			GPIO.output(self.gpio_dsdi, byte_in & (1 << i) > 0)
			GPIO.output(self.gpio_dsck, False)
			time.sleep(self.hperiod)
			# Read the bit at the rising edge of clock
			if GPIO.input(self.gpio_dsdo): byte_out |= (1 << i)
			GPIO.output(self.gpio_dsck, True)
			time.sleep(self.hperiod)
		return byte_out

	def io_bytes(self, bytes_in):
		bytes_out = bytearray()
		for byte_in in bytes_in: bytes_out.append(self.io_byte(byte_in))
		return bytes_out

	def readWord(self, address):
		self.io_bytes(b'\x04' + bytes([0x7F, 0xD6, 0x9A, 0xA6]))
		self.io_bytes(b'\x05' + address.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + bytes([0x83, 0xFE, 0x00, 0x00]))
		self.io_bytes(b'\x03' + b'\x80')
		self.io_bytes(b'\x03' + b'\x80')
		self.io_bytes(b'\x04' + bytes([0x7F, 0xF6, 0x9B, 0xA6]))
		data = self.io_bytes(b'\x04' + bytes([0x7C, 0x00, 0x00, 0x38]))[1:5]
		return data

	def writeWord(self, address, data):
		self.io_bytes(b'\x04' + bytes([0x7F, 0xF6, 0x9A, 0xA6]))
		self.io_bytes(b'\x05' + data)
		self.io_bytes(b'\x04' + bytes([0x7F, 0xD6, 0x9A, 0xA6]))
		self.io_bytes(b'\x05' + address.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + bytes([0x93, 0xFE, 0x00, 0x00]))
		self.io_bytes(b'\x03' + b'\x80')
		self.io_bytes(b'\x03' + b'\x80')

	def download(self, address, size, filename):
		self.log("BDM Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
		if(size % 4 != 0):
			raise BDMException("Size is not a multiple of 4")
		with open(filename,'wb') as f:
			while(size > 0):
				chunk = self.readWord(address)
				f.write(chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
				size -= 4
			self.progress_end()

	def verify(self, address, filename, offset=0, size=None):
		if(not size): size = os.path.getsize(filename) - offset
		self.log("BDM Verify "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		if(size % 4 != 0):
			raise BDMException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			f.seek(offset)
			while(size > 0):
				f_chunk = f.read(4)
				if(len(f_chunk) != 4): break # EOF
				chunk = self.readWord(address)
				if(f_chunk != chunk):
					raise BDMException("BDM Verify failed! @ "+hex(address))
				self.progress() # One dot every 4 Bytes
				address += 4
				size -= 4
			self.progress_end()

	def upload(self, address, filename, offset=0, size=None):
		if(not size): size = os.path.getsize(filename) - offset
		self.log("BDM Upload "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		if(size % 4 != 0):
			raise BDMException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			f.seek(offset)
			while(size > 0):
				chunk = f.read(4)
				if(len(chunk) != 4): break # EOF
				self.writeWord(address, chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
				size -= 4
			self.progress_end()

	def test(self, freeram_address):
		test = b'\xDE\xAD\xBE\xEF'
		self.writeWord(freeram_address, test)
		if(test != self.readWord(freeram_address)):
			raise BDMException("Word readback failed!")

if __name__ == "__main__":
	print("Stupid BDM-Programmer for Lotus T4e ECU\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-o",
		"--operation",
		required=False,
		type=str,
		help=
			"The action to do: "
			"ufp -> Upload Flash Program, "
			"vfp -> Verify Flash Program, "
			"sfp -> Start Flash Program, "
			"t -> Tests",
		choices=["ufp", "vfp", "sfp", "t"],
		default="t"
	)
	args = vars(ap.parse_args())
	bdm_op = args['operation']

	bdm = BDM_PI();
	bdm.openGPIO()

	print("Ready... Power UP the ECU!... Continue in 3 seconds...")
	time.sleep(3)

	if(bdm_op == 'ufp'):
		print("Upload Flash Program")
		bdm.upload(0x3FF000, "flasher/canstrap.bin")

	if(bdm_op == 'vfp'):
		print("Verify Flash Program")
		bdm.verify(0x3FF000, "flasher/canstrap.bin")

	if(bdm_op == 'sfp'):
		print("Start Flash Program")
		print("TODO!!!")

	if(bdm_op == 't'):
		print("Test ECU Read/Write")
		bdm.test(0x3FF000)

	print("Done")
