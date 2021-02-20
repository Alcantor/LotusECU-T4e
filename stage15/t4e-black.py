#!/usr/bin/python3

import sys, can, argparse
from lib.crc import CRC8Normal

class ECUBlackException(Exception):
	pass

class ECU_T4E_BLACK:
	errors = {
		0x81: "Not a 7,1 or 8,0 or 9,0 message received",
		0x82: "Error count > 3 (too many Errors)",
		0x83: "Stage3: r13-0x7FED Bit 2 is not set",
		0x85: "Error during flash programming (Hardware related, verify failed - multiple causes)",
		0x87: "Message 9,1 related ?",
		0x88: "Error during flash erase",
		0x89: "Databyte0 of expected First/Next/Subsequent Frame message was not 0x6",
		0x8A: "Programmed Bootloader Version is 0x0 and destination flash address was not 0xA00. Decrypted header Min/Max Bootloader versions are not matching or are zero",
		0x8B: "Decrypted header 'T4E'+0x1F<0x20> is not matching !",
		0x8C: "Header A00_val1(+0x34) > flashed 0xA00 value OR Header A00_val2(+0x38) < flashed 0xA00 value",
		0x8D: "Stage3: when flashing 0x10000 and payload is bigger than 65532 bytes",
		0x8E: "Timeout while waiting for data.",
		0x8F: "Test for emptiness of the flash destination address failed. This is valid for 0xA00, 0xA2C, 0xA4C, 0x7C0 (SPI) addresses",
		0x90: "HC908: Error unlocking HC908 with 8 byte passphrase",
		0x96: "More than 0x400 byte received in frame",
		0x97: "First/Next/Subsequent Frame message (0x6) had invalid len (<6 bytes) and/or the CRC was invalid",
		0x98: "Databyte1/2 of expected First/Next/Subsequent Frame message (0x6) did not match the expected frame count value",
		0x99: "Databyte 3/4 of the expected First/Next/Subsequent Frame message (0x6) did not match (total number of frame bytes received)-6 or unknown"
	}

	def __init__(self, bus, crp_file):
		self.bus = bus
		self.crc = CRC8Normal(0x31, initvalue=0x00)
		self.frames = []
		with open(crp_file, 'rb') as fcrp:
			while(True):
				chunk = fcrp.read(128)
				chunk_size = len(chunk)
				if(chunk_size == 0): break # EOF
				self.frames += [chunk]

	def send(self, cmd, data, withCRC=True):
		data = cmd.to_bytes(1, "big") + data
		if(withCRC):
			self.crc.reset()
			self.crc.update(data)
			data += self.crc.get().to_bytes(1, "big")
		if(len(data) > 8): raise ECUBlackException("Too much data!")
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x50,
			data = data
		)
		self.bus.send(msg)

	def send_frame(self, frame_id):
		frame = self.frames[frame_id]
		data = frame_id.to_bytes(2, "big") + len(frame).to_bytes(2, "big") + frame
		self.crc.reset()
		offset = 0
		size = len(data)
		while(size > 0):
			chunk_size = min(7, size)
			chunk = data[offset:offset+chunk_size]
			self.crc.update(chunk)
			if(chunk_size < 7): # Last chunk
				data += self.crc.get().to_bytes(1, "big")
			self.send(6, chunk, False)
			offset += chunk_size
			size -= chunk_size

	def recv(self, timeout=1.0):
		msg = self.bus.recv(timeout)
		if(msg == None): raise ECUBlackException("No answer!")
		self.crc.reset()
		self.crc.update(msg.data[0:-1])
		if(self.crc.get() != msg.data[-1]):
			raise ECUBlackException("Wrong CRC!")
		return (msg.data[0], msg.data[1:])

	def bootstrap(self, timeout=60.0):
		while(True):
			cmd, data = self.recv(timeout=timeout)
			# Hello
			if(cmd == 0x0A):
				print("Hello received from ECU")
				self.send(7, b"\x01\x00\x00\x00\x00\x00")
			# Frame request
			if(cmd == 0x01):
				frame_id = int.from_bytes(data[4:5], "big")
				print("Frame "+str(frame_id)+" request from ECU")
				self.send_frame(frame_id)
			# Erase Info
			if(cmd == 0x03):
				print("Erase completed received from ECU")
			# Programming Info
			if(cmd == 0x02):
				print("Programming completed received from ECU")
			# Error
			if(cmd == 0x05):
				print("Error received from ECU\n")
				error = data[4]
				print("Error "+hex(error)+": "+ECU_T4E_BLACK.errors[error])

if __name__ == "__main__":
	print("CRP Uploader for T4e Black ECU\n")
	print("\nUNTESTED! Do NOT use!\nThis is NOT safe!\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-i",
		"--interface",
		required=False,
		type=str,
		help="The CAN-Bus interface to use.",
		default="socketcan"
	)
	ap.add_argument(
		"-d",
		"--device",
		required=False,
		type=str,
		help="The CAN-Bus device to use.",
		default="can0"
	)
	args = vars(ap.parse_args())
	can_if = args['interface']
	can_ch = args['device']

	print("Open CAN "+can_if+" "+str(can_ch)+" @ 500 kbit/s")
	bus = can.Bus(
		interface = can_if,
		channel = can_ch,
		can_filters = [{"extended": False, "can_id": 0x7A1, "can_mask": 0x7FF }],
		bitrate = 500000
	)

	t4e = ECU_T4E_BLACK(bus,"stage15/black/bootldr.crp");
	print("Turn IGN on with 60sec.")
	t4e.bootstrap()
	bus.shutdown()
	print("Done")

