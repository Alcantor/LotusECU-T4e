import serial, argparse
from lib.crp01 import CRP01, CRP01_exception
from lib.fileprogress import Progress

# Some constants
BO_BE = 'big'

class CRP01_uploader:
	def __init__(self, p):
		self.p = p
		self.ser = None
		self.frame_size = 64

	def open_com(self, port):
		if(self.ser != None): self.close_com()
		self.p.log(f"Open COM {port} @ 29.7 kbit/s")
		self.ser = serial.Serial(port=port, baudrate=29761, timeout=0.1)

	def close_com(self):
		if(self.ser == None): return
		self.p.log("Close COM")
		self.ser.close()
		self.ser = None

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
		data = length.to_bytes(1, BO_BE) + cmd.to_bytes(1, BO_BE) + payload
		cksum = sum(data) & 0xFF
		data += cksum.to_bytes(1, BO_BE)
		self.ser.write(data)
		# Receive the echo
		if self.ser.read(len(data)) != data:
			raise CRP01_exception("No echo!")
		# Receive the acknowledgement
		ack = self.ser.read(1)
		if(len(ack) == 0 or ack[0] != (~cksum & 0xFF)):
			raise CRP01_exception("No acknowledgement!")

	# A packet from the ECU follows the same structure.
	#
	# Cmd:
	#	0x72: Ok, next frame (1 byte data, error code)
	def recv(self, timeout=10.0):
		# Recv
		for _ in range(0, int(timeout/self.ser.timeout)):
			data = self.ser.read(1)
			if(len(data) > 0): break
		if(len(data) == 0): raise CRP01_exception("No answer!")
		length = data[0]
		data += self.ser.read(length+1) # +1 for the sum byte
		if(len(data) != length+2): # +2 for the length and the sum bytes
			raise CRP01_exception("Missing bytes!")
		cmd, payload, cksum = data[1], data[2:-1], data[-1]
		# Check the checksum
		if(cksum != (sum(data[:-1]) & 0xFF)):
			raise CRP01_exception("Wrong checksum!")
		# Send the acknowledgement
		ack = (~cksum & 0xFF).to_bytes(1, BO_BE)
		self.ser.write(ack)
		self.ser.read(len(ack)) # Acknowledgement echo
		return (cmd, payload)

	# Wait on the ECU.
	def wait(self):
		cmd, payload = self.recv()
		if(cmd == 0x72 and len(payload) == 1):
			if(payload[0] == 0): return
			raise CRP01_exception(f"ECU: Error {payload[0]:d}")
		raise CRP01_exception(f"ECU: Unexcepted command {cmd:02X}")

	# Wait the ECU to be turned on and automatically flash it!
	def bootstrap(self, crp, timeout=60, ui_cb=lambda:None):
		self.p.log("--> Drive the L-Line down yourself! (Modify the VAG-Cable) <--\n")
		self.p.log(f"Power On ECU, please! (within {timeout:d} seconds)")
		while(True):
			ui_cb()
			try:
				self.send(0x71)
				break
			except CRP01_exception:
				self.ser.reset_input_buffer()
			timeout -= self.ser.timeout
			if(timeout <= 0): raise CRP01_exception("Time out!")
		self.p.log("ECU: In stage II")
		# Send the CRP
		self.p.progress_start(len(crp.file_data))
		offset = 0
		while(offset < len(crp.file_data)):
			self.send(0x70, crp.file_data[offset:offset+self.frame_size])
			self.wait()
			self.p.progress(self.frame_size)
			offset += self.frame_size
		self.p.progress_end()
		# Exit
		self.send(0x73)
		self.wait()
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

	crp = CRP01(None)
	crp.read_file(crp_file)	
	up = CRP01_uploader(Progress());
	up.open_com(ser_dev)
	try:
		up.bootstrap(crp)
	finally:
		up.close_com()

