#!/usr/bin/python3

import os, sys, can, argparse

class FlasherException(Exception):
	pass

class Flasher:
	blocks = [
		("Flash Boot Loader", 0x80, 0x000000, 0x10000, "bootldr.bin"),
		("Flash Calibration", 0x40, 0x010000, 0x10000, "calrom.bin"),
		("Flash Program"    , 0x3F, 0x020000, 0x60000, "prog.bin"),
		("Flash Full"       , 0xFF, 0x000000, 0x80000, "dump.bin")
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
			can_filters = [{"can_id": 0x7A0, "can_mask": 0x7FF }],
			bitrate = 1000000
		)

	def closeCAN():
		self.bus.shutdown()

	def echo(self, data):
		#self.log("Flasher Echo "+data)
		if(len(data) > 7):
			raise FlasherException("Echo too big")
		cmd = 0x00
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + data
		)
		self.bus.send(msg)
		rmsg = self.bus.recv(timeout=1.0)
		if(rmsg == None): raise FlasherException("Echo failed!")
		if(rmsg.data != msg.data):
			raise FlasherException("Unexpected answer!")

	def readWord(self, address):
		#self.log("Flasher Read Word @ "+hex(address))
		cmd = 0x01
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Read Word failed!")
		if(msg.dlc != 5 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		return msg.data[1:]

	def writeWord(self, address, data):
		#self.log("Flasher Write Word @ "+hex(address))
		cmd = 0x02
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + data
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Write Word failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def eraseBlock(self, blocks_mask):
		#self.log("Flasher Erase Block BM: "+hex(blocks_mask))
		cmd = 0x03
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + blocks_mask.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=5.0)
		if(msg == None): raise FlasherException("Erase Block failed!")
		if(msg.dlc != 2 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		if(msg.data[1] != 1):
			raise FlasherException("No PEGOOD!")

	def startProgramBlock(self, blocks_mask):
		#self.log("Flasher Start Program Block BM: "+hex(blocks_mask))
		cmd = 0x04
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + blocks_mask.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Start Program Block failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def programBlockWord(self, address, data):
		#self.log("Flasher Program Block Word @ "+hex(address)))
		cmd = 0x05
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + data
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Erase Block failed!")
		if(msg.dlc != 2 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		if(msg.data[1] != 1):
			raise FlasherException("No PEGOOD!")

	def stopProgramBlock(self):
		#self.log("Flasher Stop Program Block")
		cmd = 0x06
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Stop Program Block failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def resetECU(self):
		#self.log("Flasher reset ECU")
		cmd = 0x07
		msg = can.Message(
			arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Reset ECU failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def download(self, address, size, filename):
		self.log("Flasher Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'wb') as f:
			while(size > 0):
				chunk = self.readWord(address)
				f.write(chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
				size -= 4
			self.progress_end()

	def verify(self, address, filename):
		size = os.path.getsize(filename)
		self.log("Flasher Verify "+str(size)+" bytes @ "+hex(address)+" from "+filename)
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			while(True):
				f_chunk = f.read(4)
				if(len(f_chunk) != 4): break # EOF
				chunk = self.readWord(address)
				if(f_chunk != chunk):
					raise FlasherException("Flasher Verify failed! @ "+hex(address))
				self.progress() # One dot every 4 Bytes
				address += 4
			self.progress_end()

	def verify_blank(self, address, size):
		self.log("Flasher Verify Blank "+str(size)+" bytes @ "+hex(address))
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		while(size > 0):
			chunk = self.readWord(address)
			if(b'\xFF\xFF\xFF\xFF' != chunk):
				raise FlasherException("Flasher Verify Blank failed!")
			self.progress() # One dot every 4 Bytes
			address += 4
			size -= 4
		self.progress_end()

	def upload(self, address, filename):
		size = os.path.getsize(filename)
		self.log("Flasher Upload "+str(size)+" bytes @ "+hex(address)+" from "+filename)
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			while(True):
				chunk = f.read(4)
				if(len(chunk) != 4): break # EOF
				self.writeWord(address, chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
			self.progress_end()

	def program(self, block_mask, address, filename):
		size = os.path.getsize(filename)
		self.log("Flasher Program "+str(size)+" bytes @ "+hex(address)+" from "+filename)
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			self.startProgramBlock(block_mask)
			while(True):
				chunk = f.read(4)
				if(len(chunk) != 4): break # EOF
				self.programBlockWord(address, chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
			self.stopProgramBlock()
			self.progress_end()

	def test(self, freeram_address):
		self.echo(b'Hi ;-)')
		test = b'\xDE\xAD\xBE\xEF'
		self.writeWord(freeram_address, test)
		if(test != self.readWord(freeram_address)):
			raise FlasherException("Word readback failed!")
		self.upload(freeram_address, "injection/deadloop.bin")
		self.verify(freeram_address, "injection/deadloop.bin")

	def testFlash(self):
		blank = b'\xFF\xFF\xFF\xFF'
		test = b'\xDE\xAD\xBE\xEF'
		addr = 0x1FFF0
		data = self.readWord(addr)
		print(data)
		if(blank != data):
			raise FlasherException("Cannot test here!")
		self.startProgramBlock(0x40)
		self.programBlockWord(addr, test)
		self.stopProgramBlock()
		data = self.readWord(addr)
		if(test != data):
			print("Hu?:"+str(data))
			raise FlasherException("Word readback failed!")

if __name__ == "__main__":
	print("Stupid flasher for Lotus T4e ECU\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-i",
		"--interface",
		required=False,
		type=str,
		help="The CAN-Bus interface to use.",
		default="ixxat"
	)
	ap.add_argument(
		"-d",
		"--device",
		required=False,
		type=str,
		help="The CAN-Bus device to use.",
		default="0"
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
			"vb -> Verify blank, "
			"vfp -> Verify Flasher Program, "
			"e -> Erase Flash, "
			"p -> Program Flash, "
			"r -> Rest ECU, "
			"t -> Tests",
		choices=["dl", "v", "vb", "vfp", "e", "p", "r", "t"],
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
		"-b",
		"--block",
		nargs='*',
		type=int,
		help="Specify a block",
		choices=range(0, len(Flasher.blocks)),
		default=(1,)
	)
	ap.add_argument(
		"-lb",
		"--listblock",
		action='store_true',
		required=False,
		help="List the availables blocks",
		default=False
	)
	args = vars(ap.parse_args())
	can_if = args['interface']
	can_ch = args['device']
	ecu_op = args['operation']
	ecu_dir = args['directory']
	ecu_blocks = args['block']
	if(args['listblock']):
		print("Blocks ECU")
		for i in range(0, len(Flasher.blocks)):
			print("%i: %s" % (i, Flasher.blocks[i][0]))
		sys.exit(0)

	fl = Flasher();
	fl.openCAN(can_if, can_ch)
	print()

	if(ecu_op == 'dl'):
		print("Download ECU")
		for i in ecu_blocks:
			fl.download(
				Flasher.blocks[i][2],
				Flasher.blocks[i][3],
				ecu_dir+"/"+Flasher.blocks[i][4]
			)

	if(ecu_op == 'v'):
		print("Verify ECU")
		for i in ecu_blocks:
			fl.verify(
				Flasher.blocks[i][2],
				ecu_dir+"/"+Flasher.blocks[i][4]
			)

	if(ecu_op == 'vb'):
		print("Verify Blank ECU")
		for i in ecu_blocks:
			fl.verify_blank(
				Flasher.blocks[i][2],
				Flasher.blocks[i][3]
			)

	if(ecu_op == 'vfp'):
		print("Verify Flasher Program")
		fl.verify(0x3FF000,"injection/flasher.bin")

	if(ecu_op == 'e'):
		print("Erase ECU Flash")
		for i in ecu_blocks:
			print("Erase "+Flasher.blocks[i][0])
			fl.eraseBlock(Flasher.blocks[i][1])

	if(ecu_op == 'p'):
		print("Program ECU Flash")
		for i in ecu_blocks:
			fl.program(
				Flasher.blocks[i][1],
				Flasher.blocks[i][2],
				ecu_dir+"/"+Flasher.blocks[i][4]
			)

	if(ecu_op == 'r'):
		print("Reset ECU")
		fl.resetECU()

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		#fl.testFlash()
		fl.test(0x3F8000)

	fl.closeCAN()
	print("Done")
