#!/usr/bin/python3

import os, sys, can, argparse
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

	# Override it if needed
	def log(self, msg):
		print(msg)

	# Override it if needed
	def progress(self):
		print(".", end="", flush=True)

	# Override it if needed
	def progress_end(self):
		print()

	def openCAN(self, interface, channel):
		self.log("Open CAN "+interface+" "+str(channel)+" @ 1 Mbit/s")
		self.bus = can.Bus(
			interface = interface,
			channel = channel,
			can_filters = [{"extended": False, "can_id": 0x7A0, "can_mask": 0x7FF }],
			bitrate = 1000000
		)

	def closeCAN(self):
		self.bus.shutdown()

	def readMemory(self, address, size):
		#self.log("ECU Read "+str(size)+" bytes @ "+hex(address))
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x50,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Word failed!")
			if(msg.dlc != 4): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x51,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Half failed!")
			if(msg.dlc != 2): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x52,
				data = address.to_bytes(4, "big")
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Byte failed!")
			if(msg.dlc != 1): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size < 256):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x53,
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

	def writeMemory(self, address, data, verify = True):
		size = len(data)
		#self.log("ECU Write "+str(data)+" @ "+hex(address))
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x54,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x55,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x56,
				data = address.to_bytes(4, "big") + data
			)
			self.bus.send(msg)
		elif(size < 256):
			offset = 0
			msg = can.Message(
				is_extended_id = False,	arbitration_id = 0x57,
				data = address.to_bytes(4, "big") + size.to_bytes(1, "big")
			)
			self.bus.send(msg)
			while(size > 0):
				chunk_size = min(8, size)
				msg = can.Message(
					is_extended_id = False,	arbitration_id = 0x57,
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
		self.log("ECU Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
		with open(filename,'wb') as f:
			while(size > 0):
				chunk_size = min(128, size);
				chunk = self.readMemory(address, chunk_size)
				f.write(chunk)
				self.progress() # One dot every 128 Bytes
				address += chunk_size
				size -= chunk_size
			self.progress_end()

	def verify(self, address, filename):
		size = os.path.getsize(filename)
		self.log("ECU Verify "+str(size)+" bytes @ "+hex(address)+" from "+filename)
		with open(filename,'rb') as f:
			while(True):
				f_chunk = f.read(128)
				chunk_size = len(f_chunk)
				if(chunk_size == 0): break # EOF
				chunk = self.readMemory(address, chunk_size)
				if(f_chunk != chunk):
					raise ECUException("ECU Verify failed! @ "+hex(address))
				self.progress() # One dot every 128 Bytes
				address += chunk_size
			self.progress_end()

	def upload(self, address, filename):
		size = os.path.getsize(filename)
		self.log("ECU Upload "+str(size)+" bytes @ "+hex(address)+" from "+filename)
		with open(filename,'rb') as f:
			while(True):
				chunk = f.read(128)
				chunk_size = len(chunk)
				if(chunk_size == 0): break # EOF
				self.writeMemory(address, chunk)
				self.progress() # One dot every 128 Bytes
				address += chunk_size
			self.progress_end()

	def inject(self, freeram_address, filename, stackblr_address):
		self.upload(freeram_address, filename)
		self.writeMemory(stackblr_address, freeram_address.to_bytes(4, "big"), False)
		fl = Flasher()
		fl.bus = self.bus
		fl.log = self.log
		fl.bootstrap(timeout=1.0)

	def test(self, freeram_address):
		# Word
		self.writeMemory(freeram_address, b'\xDE\xAD\xBE\xEF')
		# 3 Bytes
		self.writeMemory(freeram_address, b'\x11\x22\x33')
		# Half
		self.writeMemory(freeram_address, b'\xAA\x55')
		# Byte
		self.writeMemory(freeram_address, b'\x10')
		# Much more
		self.writeMemory(freeram_address, b'Hello world')

if __name__ == "__main__":
	print("Stupid dumper for Lotus T4e ECU\n")
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

	t4e = ECU_T4E();
	t4e.openCAN(can_if, can_ch)
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
		#t4e.inject(0x3FF000, "injection/deadloop.bin", 0x3FFFDC)
		t4e.inject(0x3FF000, "injection/flasher.bin", 0x3FFFDC)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		t4e.test(0x3FF000)

	t4e.closeCAN()
	print("Done")
