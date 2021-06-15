#!/usr/bin/python3

import serial, argparse
from lib.crp05 import CRP05, CRP05_exception
from lib.fileprogress import Progress

class CRP05_uploader:
	def __init__(self, port, p):
		self.ser = serial.Serial(port=port, baudrate=29761, timeout=0.1)
		self.p = p
		self.frame_size = 96
		
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
	#	0x70: CRP Data
	#	0x73: Exit (no data)
	def send(self, cmd, payload = b''):
		# Send
		length = len(payload) + 1 # +1 for the cmd byte
		data = length.to_bytes(1, "big") + cmd.to_bytes(1, "big") + payload
		cksum = sum(data) & 0xFF
		data += cksum.to_bytes(1, "big")
		self.ser.write(data)
		# Receive the echo
		if self.ser.read(len(data)) != data:
			raise CRP05_exception("No echo!")
		# Receive the acknowledgement
		ack = self.ser.read(1)
		if(len(ack) == 0 or ack[0] != (~cksum & 0xFF)):
			raise CRP05_exception("No acknowledgement!")

	# A packet from the ECU follows the same structure.
	#
	# Cmd:
	#	0x72: Ok, next frame (1 byte data, error code)
	def recv(self):
		# Recv
		data = self.ser.read(1)
		while(len(data) == 0): data = self.ser.read(1)
		length = data[0]
		data += self.ser.read(length+1) # +1 for the sum byte
		if(len(data) != length+2): # +2 for the length and the sum bytes
			raise CRP05_exception("Missing bytes!")
		cmd, payload, cksum = data[1], data[2:-1], data[-1]
		# Check the checksum
		if(cksum != (sum(data[:-1]) & 0xFF)):
			raise CRP05_exception("Wrong checksum!")
		# Send the acknowledgement
		ack = (~cksum & 0xFF).to_bytes(1, "big")
		self.ser.write(ack)
		self.ser.read(len(ack)) # Acknowledgement echo
		return (cmd, payload)

	# Wait the ECU to be turned on and automatically flash it!
	def bootstrap(self, crp):
		self.p.log("--> Drive the L-Line down yourself! (Modify the VAG-Cable) <--\n")
		self.p.log("Power On ECU, please!")
		while(True):
			msg = self.ser.read(1024)
			#print(msg)
			if  (msg == b'\x00\x00\x00'): break
		self.p.log("ECU: Hello")
		self.send(0x71)
		self.p.log("ECU: In stage II")
		# Send the CRP
		self.p.progress_start(len(crp.file_data))
		for frame_id in range(0, len(crp.file_data)//self.frame_size):
			offset = frame_id * self.frame_size
			self.send(0x70, crp.file_data[offset:offset+self.frame_size])
			cmd, payload = self.recv()
			if(cmd == 0x72 and len(payload) == 1):
				if(payload[0] == 0):
					self.p.progress(self.frame_size)
				else:
					raise CRP05_exception("ECU: Unknow code: "+str(payload[0]))
		self.p.progress_end()
		# Exit
		#self.send(0x73)
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
	
	up = CRP05_uploader(ser_dev, Progress());
	crp = CRP05(True)
	crp.read_file(crp_file)
	up.bootstrap(crp)

