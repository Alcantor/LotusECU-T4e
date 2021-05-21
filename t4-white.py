#!/usr/bin/python3

import serial, argparse
from lib.fileprogress import Progress

class ECUWhiteException(Exception):
	pass

class ECU_T4_WHITE:
	def __init__(self, port, p):
		self.ser = serial.Serial(port=port, baudrate=29761, timeout=0.1)
		self.p = p
		self.frame_size = 64
		
	# A packet to the ECU is:
	#	1 byte length (excluding checksum)
	#	1 byte command
	#	x bytes data
	#	1 byte sum
	#
	# The ECU acknowlegde the reception by sending the inverted of the sum.
	#
	# Raise an Exception if the ECU does not acknowledge
	#
	# Cmd:
	#	0x71: Enter stage II at speed 29761 (no data)
	#	0x81: Enter stage II at speed 29069 (no data)
	#	0x72: CRP Data
	#	0x73: Exit (no data)
	def send(self, cmd, data = b''):
		# Send
		data = cmd.to_bytes(1, "big") + data
		data = len(data).to_bytes(1, "big") + data
		cksum = sum(data) & 0xFF
		data = data + cksum.to_bytes(1, "big")
		self.ser.write(data)
		# Receive the echo + the acknowledgement
		cksum = ~cksum & 0xFF
		data = data + cksum.to_bytes(1, "big")
		if self.ser.read(len(data)) != data:
			raise ECUWhiteException("No acknowledgement!")

	def bootstrap(self, crp_file):
		self.p.log("--> Drive the L-Line down yourself! (Modify the VAG-Cable) <--\n")
		self.p.log("Power On ECU, please!")
		with open(crp_file, 'rb') as fcrp:
			data_crp = fcrp.read()
		while(True):
			msg = self.ser.read(1024)
			#print(msg)
			if  (msg == b'\x00\x00\x00'): break
		self.p.log("ECU: Hello")
		self.send(0x71)
		self.p.log("ECU: In stage II")
		# Send the CRP
		self.p.progress_start(len(data_crp))
		for frame_id in range(0, len(data_crp)//self.frame_size):
			self.p.progress(self.frame_size)
			offset = frame_id * self.frame_size
			self.send(0x72, data_crp[offset:offset+self.frame_size])
		self.p.progress_end()
		# Exit
		self.send(0x73)
		self.p.log("ECU: Done")

if __name__ == "__main__":
	print("CRP Uploader for T4/T4E White ECU - with a VAG-Cable\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-d",
		"--device",
		required=False,
		type=str,
		help="The serial device to use.",
		default="/dev/ttyUSB0"
	)
	ap.add_argument(
		"-f",
		"--file",
		required=True,
		type=str,
		help="The CRP file to upload"
	)
	args = vars(ap.parse_args())
	ser_dev = args['device']
	crp_file = args['file']
	
	t4 = ECU_T4_WHITE(ser_dev, Progress());
	t4.bootstrap(crp_file)

