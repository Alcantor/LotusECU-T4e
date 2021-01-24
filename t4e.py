#!/usr/bin/python3

import sys, can, argparse
from lib.fileprogress import FileProgress
from flasher import Flasher

class ECUException(Exception):
	pass

class ECU_T4E:
	zones = [
		("ROM Boot Loader", 0x000000, 0x10000, "bootldr.bin"),
		("ROM Calibration", 0x010000, 0x10000, "calrom.bin"),
		("ROM Program"    , 0x020000, 0x60000, "prog.bin"),
		("RAM Persistant" , 0x2F8000, 0x00800, "decram.bin"),
		("RAM Main"       , 0x3F8000, 0x08000, "calram.bin"),
		("ROM Full"       , 0x000000, 0x80000, "dump.bin")
	]

	def __init__(self, bus, fp):
		self.bus = bus
		self.fp = fp

	def readMemory(self, address, size):
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x50,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Word failed!")
			if(msg.dlc != 4): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x51,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Half failed!")
			if(msg.dlc != 2): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x52,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Byte failed!")
			if(msg.dlc != 1): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size < 256):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x53,
				data = address.to_bytes(4, "big") + size.to_bytes(1, "big")
			)
			self.bus.send(msg)
			data = bytearray()
			while(size > 0):
				chunk_size = min(8, size);
				msg = self.bus.recv(timeout=1.0)
				if(msg == None): raise ECUException("ECU Read Buffer failed!")
				if(msg.dlc != chunk_size): raise ECUException("Unexpected answer!")
				data += msg.data
				size -= chunk_size
		else:
			raise ECUException("ECU Read too much bytes!")
		return data

	def writeMemory(self, address, data, verify = False):
		size = len(data)
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x54,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x55,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x56,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size < 256):
			offset = 0
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x57,
				data = address.to_bytes(4, "big") + size.to_bytes(1, "big")
			)
			self.bus.send(msg)
			while(size > 0):
				chunk_size = min(8, size)
				msg = can.Message(
					is_extended_id = False, arbitration_id = 0x57,
					data = data[offset:offset+chunk_size]
				)
				self.bus.send(msg)
				size -= chunk_size
				offset += chunk_size
		else:
			raise ECUException("ECU Write too much bytes!")
		if(verify and data != self.readMemory(address, len(data))):
			raise ECUException("ECU Write failed!")

	def download(self, address, size, filename):
		self.fp.download(address, size, filename, self.readMemory, 128, False)

	def verify(self, address, filename):
		self.fp.verify(address, filename, self.readMemory, 128, False)

	def upload(self, address, filename):
		self.fp.upload(address, filename, self.writeMemory, 128, False)

	def inject(self, freeram_address, filename, stackblr_address):
		self.upload(freeram_address, filename)
		self.writeMemory(stackblr_address, freeram_address.to_bytes(4, "big"))

	def test(self, freeram_address):
		# Word
		self.writeMemory(freeram_address, b'\xDE\xAD\xBE\xEF', True)
		# 3 Bytes
		self.writeMemory(freeram_address, b'\x11\x22\x33', True)
		# Half
		self.writeMemory(freeram_address, b'\xAA\x55', True)
		# Byte
		self.writeMemory(freeram_address, b'\x10', True)
		# Much more
		self.writeMemory(freeram_address, b'Hello world', True)

if __name__ == "__main__":
	print("Dumper for Lotus T4e ECU\n")
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
	ap.add_argument(
		"-o",
		"--operation",
		required=False,
		type=str,
		help=
			"The action to do: "
			"dl -> Download, "
			"v -> Verify, "
			"ifp -> Inject Flash Program, "
			"t -> Tests",
		choices=["dl", "v", "ifp", "t"],
		default="dl"
	)
	ap.add_argument(
		"-D",
		"--directory",
		required=False,
		type=str,
		help="Dump directory",
		default="."
	)
	ap.add_argument(
		"-z",
		"--zone",
		nargs='*',
		type=int,
		help="Specify a zone",
		choices=range(0, len(ECU_T4E.zones)),
		default=range(0, 5)
	)
	ap.add_argument(
		"-lz",
		"--listzone",
		action='store_true',
		required=False,
		help="List the availables zones",
		default=False
	)
	args = vars(ap.parse_args())
	can_if = args['interface']
	can_ch = args['device']
	ecu_op = args['operation']
	ecu_dir = args['directory']
	ecu_zones = args['zone']
	if(args['listzone']):
		print("Zones ECU")
		for i in range(0, len(ECU_T4E.zones)):
			print("%i: %s" % (i, ECU_T4E.zones[i][0]))
		sys.exit(0)

	print("Open CAN "+can_if+" "+str(can_ch)+" @ 1 Mbit/s")
	bus = can.Bus(
		interface = can_if,
		channel = can_ch,
		can_filters = [{"extended": False, "can_id": 0x7A0, "can_mask": 0x7FF }],
		bitrate = 1000000
	)

	t4e = ECU_T4E(bus, FileProgress());
	print()

	if(ecu_op == 'dl'):
		print("Download ECU")
		for i in ecu_zones:
			t4e.download(
				ECU_T4E.zones[i][1],
				ECU_T4E.zones[i][2],
				ecu_dir+"/"+ECU_T4E.zones[i][3]
			)

	if(ecu_op == 'v'):
		print("Verify ECU")
		for i in ecu_zones:
			t4e.verify(
				ECU_T4E.zones[i][1],
				ecu_dir+"/"+ECU_T4E.zones[i][3]
			)

	if(ecu_op == 'ifp'):
		print("Inject Flash Program")
		t4e.inject(0x3FF000, "flasher/canstrap.bin", 0x3FFFDC)
		fl = Flasher(t4e.bus, t4e.fp)
		fl.canstrap(timeout=1.0)
		print("We have the control of the ECU!")
		# Install the flasher plugin
		fl.upload(0x3FF200, "flasher/plugin_flash.bin")
		fl.plugin(0x3FF200)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		t4e.test(0x3FF000)

	bus.shutdown()
	print("Done")

