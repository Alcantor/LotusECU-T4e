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
			can_filters = [{"extended": False, "can_id": 0x7A0, "can_mask": 0x7FF }],
			bitrate = 1000000
		)

	def closeCAN(self):
		self.bus.shutdown()

	def echo(self, data=b''):
		#self.log("Flasher Echo "+data)
		if(len(data) > 7):
			raise FlasherException("Echo too big")
		cmd = 0x00
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
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
			is_extended_id = False, arbitration_id = 0x60,
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
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + data
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Write Word failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def branch(self, address, param = b''):
		#self.log("Flasher Branch @ "+hex(address))
		cmd = 0x03
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + param
		)
		self.bus.send(msg)

	def plugin(self, address):
		#self.log("Flasher run Plugin @ "+hex(address))
		cmd = 0x04
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Run Plugin failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def eraseBlock(self, blocks_mask):
		#self.log("Flasher Erase Block BM: "+hex(blocks_mask))
		cmd = 0x05
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
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
		cmd = 0x06
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + blocks_mask.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Start Program Block failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def programBlockWord(self, address, data):
		#self.log("Flasher Program Block Word @ "+hex(address)))
		cmd = 0x07
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + data
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Program Block Word failed!")
		if(msg.dlc != 2 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		if(msg.data[1] != 1):
			raise FlasherException("No PEGOOD!")

	def stopProgramBlock(self):
		#self.log("Flasher Stop Program Block")
		cmd = 0x08
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Stop Program Block failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def readEEPROMWord(self, address):
		#self.log("Flasher EEPROM Read Word @ "+hex(address))
		cmd = 0x09
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big")
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Read EEPROM Word failed!")
		if(msg.dlc != 5 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		return msg.data[1:]

	def writeEEPROMWord(self, address, data):
		#self.log("Flasher EEPROM Write Word @ "+hex(address))
		cmd = 0x0A
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + address.to_bytes(3, "big") + data
		)
		self.bus.send(msg)
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Write EEPROM Word failed!")
		if(msg.dlc != 1 or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")

	def download(self, address, size, filename, read_fnct=None):
		if(not read_fnct): read_fnct = self.readWord
		self.log("Flasher Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'wb') as f:
			while(size > 0):
				chunk = read_fnct(address)
				f.write(chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
				size -= 4
			self.progress_end()

	def verify(self, address, filename, offset=0, size=None, read_fnct=None):
		if(not size): size = os.path.getsize(filename)
		if(not read_fnct): read_fnct = self.readWord
		self.log("Flasher Verify "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			f.seek(offset)
			while(True):
				f_chunk = f.read(4)
				if(len(f_chunk) != 4): break # EOF
				chunk = read_fnct(address)
				if(f_chunk != chunk):
					raise FlasherException("Flasher Verify failed! @ "+hex(address))
				self.progress() # One dot every 4 Bytes
				address += 4
			self.progress_end()

	def verify_blank(self, address, size, read_fnct=None):
		if(not read_fnct): read_fnct = self.readWord
		self.log("Flasher Verify Blank "+str(size)+" bytes @ "+hex(address))
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		while(size > 0):
			chunk = read_fnct(address)
			if(b'\xFF\xFF\xFF\xFF' != chunk):
				raise FlasherException("Flasher Verify Blank failed! @ "+hex(address))
			self.progress() # One dot every 4 Bytes
			address += 4
			size -= 4
		self.progress_end()

	def upload(self, address, filename, offset=0, size=None, write_fnct=None):
		if(not size): size = os.path.getsize(filename)
		if(not write_fnct): write_fnct = self.writeWord
		self.log("Flasher Upload "+str(size)+" bytes @ "+hex(address)+" from "+filename+" +"+hex(offset))
		if(size % 4 != 0):
			raise FlasherException("Size is not a multiple of 4")
		with open(filename,'rb') as f:
			f.seek(offset)
			while(True):
				chunk = f.read(4)
				if(len(chunk) != 4): break # EOF
				write_fnct(address, chunk)
				self.progress() # One dot every 4 Bytes
				address += 4
			self.progress_end()

	def program(self, block_mask, address, filename, offset=0, size=None):
		try:
			self.startProgramBlock(block_mask)
			self.upload(address, filename, offset, size, self.programBlockWord)
		finally:
			self.stopProgramBlock()

	def canstrap(self, timeout=60.0):
		self.log("Flasher Canstrap")
		msg = self.bus.recv(timeout=timeout)
		if(msg == None): raise FlasherException("Time out!")
		if(msg.dlc != 6 or msg.data != b'HiCsV1'):
			raise FlasherException("Unexpected answer!")
		else:
			self.echo()
			self.log("We have the control of the ECU!")

	def test(self, freeram_address):
		self.echo(b'Hi ;-)')
		test = b'\xDE\xAD\xBE\xEF'
		self.writeWord(freeram_address, test)
		if(test != self.readWord(freeram_address)):
			raise FlasherException("Word readback failed!")
		self.upload(freeram_address, "flasher/func_test.bin")
		self.verify(freeram_address, "flasher/func_test.bin")
		self.branch(freeram_address, b'Helo')
		msg = self.bus.recv(timeout=1.0)
		if(msg == None): raise FlasherException("Test failed!")
		if(msg.dlc != 8 or msg.data != b'Helo\x01\x02\x03\x04'):
			raise FlasherException("Unexpected answer!")

if __name__ == "__main__":
	print("Stupid flasher for Lotus T4e ECU\n")
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
			"vb -> Verify blank, "
			"vfp -> Verify Flasher Program, "
			"e -> Erase Flash, "
			"p -> Program Flash, "
			"r -> Reset ECU, "
			"b -> (Boot) Canstrap from Stage 1.5, "
			"t -> Tests,"
			"dle -> Download EEPROM,"
			"ve -> Verify EEPROM,"
			"pe -> Program EEPROM",
		choices=["dl", "v", "vb", "vfp", "e", "p", "r", "b", "t", "dle", "ve", "pe"],
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
		fl.verify(0x3FF000,"flasher/canstrap.bin")
		fl.verify(0x3FF200,"flasher/plugin_flash.bin")

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

	if(ecu_op == 'b'):
		print("Turn IGN on with 60sec.")
		fl.canstrap()
		# Move the flasher to the RAM to be able to reflash the bootloader
		fl.upload(0x3FF000,"flasher/canstrap.bin")
		fl.branch(0x3FF000)
		fl.canstrap(1.0)
		fl.upload(0x3FF200,"flasher/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000,"flasher/canstrap.bin")
		fl.verify(0x3FF200,"flasher/plugin_flash.bin")

	if(ecu_op == 'r'):
		print("Reset ECU - Reboot to stage II")
		fl.branch(0x4000)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		fl.test(0x3F8000)

	if(ecu_op == 'dle'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		print("Read EEPROM (Does not work from stage15)")
		fl.upload(0x3FF600,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF600)
		fl.download(0x0, 2048, ecu_dir+"/eeprom.bin", read_fnct=fl.readEEPROMWord)
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	if(ecu_op == 've'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		print("Verify EEPROM (Does not work from stage15)")
		fl.upload(0x3FF600,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF600)
		fl.verify(0x0, ecu_dir+"/eeprom.bin", read_fnct=fl.readEEPROMWord)
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	if(ecu_op == 'pe'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		print("Program EEPROM (Does not work from stage15)")
		fl.upload(0x3FF600,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF600)
		fl.upload(0x0, ecu_dir+"/eeprom.bin", write_fnct=fl.writeEEPROMWord)
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	fl.closeCAN()
	print("Done")
