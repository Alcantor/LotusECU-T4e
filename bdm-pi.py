#!/usr/bin/python3

import sys, argparse, time
import RPi.GPIO as GPIO
from lib.fileprogress import FileProgress
from lib.ppc32 import PPC32

# DSCK -> GPIO4  - PIN7 with a 5.6 kOhm resistor
# GND  -> GND    - PIN9
# DSDI -> GPIO17 - PIN11
# DSDO -> GPIO27 - PIN13

# DSCK should be bidirectional
# Put a 5.6kOhm resistor between the ECU and the Raspberry Pi !!!
# DSCK is also pulled down with a 10 kOhm resistor on the ECU

class BDMException(Exception):
	pass

class BDM_PI:
	def __init__(self, fp):
		self.fp = fp

	def openGPIO(self, gpio_dsck=4, gpio_dsdi=17, gpio_dsdo=27, hperiod=0.0005):
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
		for i in reversed(range(8)):
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
		# See MCP561RM Table 23-13
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(30, 630))
		self.io_bytes(b'\x05' + address.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + PPC32.ppc_lwz(31, 30, 0))
		self.io_bytes(b'\x03\x80') # NOP (0x7 + 7 bits to 0)
		self.io_bytes(b'\x03\x80')
		self.io_bytes(b'\x04' + PPC32.ppc_mtspr(31, 630))
		return self.io_bytes(b'\x04' + PPC32.ppc_and(0, 0, 0))[1:5]

	def writeWord(self, address, data):
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(31, 630))
		self.io_bytes(b'\x05' + data)
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(30, 630))
		self.io_bytes(b'\x05' + address.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + PPC32.ppc_stw(31, 30, 0))
		self.io_bytes(b'\x03\x80')
		self.io_bytes(b'\x03\x80')

	def execute(self, address, msr=0x000003002):
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(30, 630))
		self.io_bytes(b'\x05' + address.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + PPC32.ppc_mtspr(30, 26)) # Set the program counter by setting SRR0
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(31, 630))
		self.io_bytes(b'\x05' + msr.to_bytes(4, "big"))
		self.io_bytes(b'\x04' + PPC32.ppc_mtspr(31, 27)) # Set SRR1 to desired MSR register
		self.io_bytes(b'\x04' + PPC32.ppc_mfspr(30, 148)) # Read the ECR register to clear out any exceptions
		self.io_bytes(b'\x04' + PPC32.ppc_rfi())

	def disableWatchdog(self):
		self.writeWord(0x2FC004, bytes([0x00, 0x00, 0xFF, 0x80]))

	def download(self, address, size, filename):
		self.disableWatchdog()
		self.fp.download(address, size, filename, self.readWord, 4, True)

	def verify(self, address, filename, offset=0, size=None):
		self.disableWatchdog()
		self.fp.verify(address, filename, self.readWord, 4, True, offset, size)

	def upload(self, address, filename, offset=0, size=None):
		self.disableWatchdog()
		self.fp.upload(address, filename, self.writeWord, 4, True, offset, size)

	def test(self, freeram_address):
		self.disableWatchdog()
		test = b'\xDE\xAD\xBE\xEF'
		self.writeWord(freeram_address, test)
		if(test != self.readWord(freeram_address)):
			raise BDMException("Word readback failed!")

if __name__ == "__main__":
	print("BDM-Programmer for Lotus T4e ECU\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-o",
		"--operation",
		required=False,
		type=str,
		help=
			"The action to do: "
			"pdh -> Pull DSCK high, "
			"ufp -> Upload Flash Program, "
			"vfp -> Verify Flash Program, "
			"sfp -> Start Flash Program, "
			"rd  -> Release DSCK, "
			"t -> Tests",
		choices=["pdh", "ufp", "vfp", "sfp", "rd", "t"],
		default="t"
	)
	args = vars(ap.parse_args())
	bdm_op = args['operation']

	bdm = BDM_PI(FileProgress());
	print("Open GPIO for BDM operation")
	bdm.openGPIO()

	if(bdm_op == 'pdh'):
		GPIO.output(bdm.gpio_dsck, True)
		GPIO.output(bdm.gpio_dsdi, False)
		print("Ready... You can power UP the ECU yet!")

	if(bdm_op == 'ufp'):
		print("Upload Flash Program")
		bdm.upload(0x3FF000, "flasher/t4e/canstrap-white.bin")

	if(bdm_op == 'vfp'):
		print("Verify Flash Program")
		bdm.verify(0x3FF000, "flasher/t4e/canstrap-white.bin")

	if(bdm_op == 'sfp'):
		print("Start Flash Program")
		bdm.execute(0x3FF000)

	if(bdm_op == 'rd'):
		print("ECU will start normally yet!")
		GPIO.setup(bdm.gpio_dsck, GPIO.IN)
		GPIO.setup(bdm.gpio_dsdi, GPIO.IN)

	if(bdm_op == 't'):
		print("Test ECU Read/Write")
		bdm.test(0x3FF000)

	print("Done")
