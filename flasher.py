#!/usr/bin/python3

import sys, can, argparse
from lib.fileprogress import FileProgress
from lib.crc import CRC32Reflect

class FlasherException(Exception):
	pass

class Flasher:
	blocks = [
		("Flash Boot Loader", 0x80, 0x000000, 0x10000, "bootldr.bin"),
		("Flash Calibration", 0x40, 0x010000, 0x10000, "calrom.bin"),
		("Flash Program"    , 0x3F, 0x020000, 0x60000, "prog.bin"),
		("Flash Full"       , 0xFF, 0x000000, 0x80000, "dump.bin")
	]

	def __init__(self, bus, fp):
		if(bus): bus.set_filters([{
			"extended": False,
			"can_id": 0x7A0,
			"can_mask": 0x7FF
		}])
		self.bus = bus
		self.fp = fp

	def send(self, cmd, data=b''):
		msg = can.Message(
			is_extended_id = False, arbitration_id = 0x60,
			data = cmd.to_bytes(1, "big") + data
		)
		self.bus.send(msg)

	def recv(self, cmd, length=0, timeout=1.0):
		msg = self.bus.recv(timeout)
		if(msg == None): raise FlasherException("No answer!")
		if(msg.dlc-1 != length or msg.data[0] != cmd):
			raise FlasherException("Unexpected answer!")
		return msg.data[1:]

	def echo(self, data=b''):
		if(len(data) > 7):
			raise FlasherException("Echo too big")
		cmd = 0x00
		self.send(cmd, data)
		rdata = self.recv(cmd, len(data))
		if(rdata != data):
			raise FlasherException("Unexpected echo!")

	def readWord(self, address):
		cmd = 0x01
		self.send(cmd, address.to_bytes(3, "big"))
		return self.recv(cmd, 4)

	def writeWord(self, address, data):
		cmd = 0x02
		self.send(cmd, address.to_bytes(3, "big") + data)
		self.recv(cmd)

	def branch(self, address, param = b''):
		cmd = 0x03
		self.send(cmd, address.to_bytes(3, "big") + param)

	def plugin(self, address):
		cmd = 0x04
		self.send(cmd, address.to_bytes(3, "big"))
		self.recv(cmd)

	def eraseBlock(self, blocks_mask):
		cmd = 0x05
		self.send(cmd, blocks_mask.to_bytes(1, "big"))
		pegood = self.recv(cmd, 1, 10.0)
		if(pegood[0] != 1):
			raise FlasherException("No PEGOOD!")

	def startProgramBlock(self, blocks_mask):
		cmd = 0x06
		self.send(cmd, blocks_mask.to_bytes(1, "big"))
		self.recv(cmd)

	def programBlockWord(self, address, data):
		cmd = 0x07
		self.send(cmd, address.to_bytes(3, "big") + data)
		pegood = self.recv(cmd, 1, 1.0)
		if(pegood[0] != 1):
			raise FlasherException("No PEGOOD!")

	def stopProgramBlock(self):
		cmd = 0x08
		self.send(cmd)
		self.recv(cmd)

	def readEEPROMWord(self, address):
		cmd = 0x09
		self.send(cmd, address.to_bytes(3, "big"))
		return self.recv(cmd, 4)

	def writeEEPROMWord(self, address, data):
		cmd = 0x0A
		self.send(cmd, address.to_bytes(3, "big") + data)
		self.recv(cmd)

	def computeCRC(self, address, length):
		cmd = 0x0B
		self.send(cmd, address.to_bytes(3, "big") + length.to_bytes(4, "big"))
		return int.from_bytes(self.recv(cmd, 4, 5.0), "big")

	def download(self, address, size, filename):
		self.fp.download(address, size, filename, self.readWord, 4, True)

	def verify(self, address, filename, offset=0, size=None):
		self.fp.verify(address, filename, self.readWord, 4, True, offset, size)

	def verify_blank(self, address, size):
		self.fp.verify_blank(address, size, self.readWord, 4, True)

	def upload(self, address, filename, offset=0, size=None):
		self.fp.upload(address, filename, self.writeWord, 4, True, offset, size)

	def downloadEEPROM(self, address, size, filename):
		self.fp.download(address, size, filename, self.readEEPROMWord, 4, True)

	def verifyEEPROM(self, address, filename, offset=0, size=None):
		self.fp.verify(address, filename, self.readEEPROMWord, 4, True, offset, size)

	def uploadEEPROM(self, address, filename, offset=0, size=None):
		self.fp.upload(address, filename, self.writeEEPROMWord, 4, True, offset, size)

	def program(self, block_mask, address, filename, offset=0, size=None):
		try:
			self.startProgramBlock(block_mask)
			self.fp.upload(address, filename, self.programBlockWord, 4, True, offset, size)
		finally:
			self.stopProgramBlock()

	def canstrap(self, timeout=60.0):
		msg = self.bus.recv(timeout=timeout)
		if(msg == None): raise FlasherException("Time out!")
		if(msg.dlc != 6 or msg.data != b'HiCsV1'):
			raise FlasherException("Unexpected answer!")
		else:
			self.echo()

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
	print("Flasher for Lotus T4e ECU\n")
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
		"-s",
		"--speed",
		required=False,
		type=str,
		help="The CAN-Bus speed.",
		choices=["white", "black"],
		default="white"
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
			"t -> Tests, "
			"dle -> Download EEPROM, "
			"ve -> Verify EEPROM, "
			"pe -> Program EEPROM, "
			"c -> Compute CRC",
		choices=["dl", "v", "vb", "vfp", "e", "p", "r", "b", "t", "dle", "ve", "pe", "c"],
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
	if(args['speed'] == 'black'):
		can_br = 500000
		canstrap_file = "flasher/canstrap-black.bin"
	else:
		can_br = 1000000
		canstrap_file = "flasher/canstrap-white.bin"
	if(args['listblock']):
		print("Blocks ECU")
		for i in range(0, len(Flasher.blocks)):
			print("%i: %s" % (i, Flasher.blocks[i][0]))
		sys.exit(0)

	print("Open CAN "+can_if+" "+str(can_ch)+" @ "+str(can_br/1000)+" kbit/s")
	bus = can.Bus(
		interface = can_if,
		channel = can_ch,
		bitrate = can_br
	)

	fl = Flasher(bus, FileProgress());
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
		fl.verify(0x3FF000,canstrap_file)
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
		print("Turn IGN on within 60sec.")
		fl.canstrap()
		# Move the flasher to the RAM to be able to reflash the bootloader
		fl.upload(0x3FF000,canstrap_file)
		fl.branch(0x3FF000)
		fl.canstrap(1.0)
		fl.upload(0x3FF200,"flasher/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000,canstrap_file)
		fl.verify(0x3FF200,"flasher/plugin_flash.bin")

	if(ecu_op == 'r'):
		print("Reset ECU - Reboot")
		fl.branch(0x100)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		fl.test(0x3F8000)

	if(ecu_op == 'dle'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		#fl.upload(0x3FF600,"flasher/func_eeprom_init.bin")
		#fl.branch(0x3FF600)
		print("Read EEPROM (Does not work from stage15)")
		fl.upload(0x3FF300,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF300)
		fl.downloadEEPROM(0x0, 2048, ecu_dir+"/eeprom.bin")
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	if(ecu_op == 've'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		#fl.upload(0x3FF600,"flasher/func_eeprom_init.bin")
		#fl.branch(0x3FF600)
		print("Verify EEPROM (Does not work from stage15)")
		fl.upload(0x3FF300,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF300)
		fl.verifyEEPROM(0x0, ecu_dir+"/eeprom.bin")
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	if(ecu_op == 'pe'):
		#print("Upload TPU Microcode (EEPROM CS is on TPU)")
		#fl.upload(0x302000,"dump/A128E6009F/prog.bin", 0x45D20, 0x800)
		#fl.upload(0x3FF600,"flasher/func_eeprom_init.bin")
		#fl.branch(0x3FF600)
		print("Program EEPROM (Does not work from stage15)")
		fl.upload(0x3FF300,"flasher/plugin_eeprom.bin")
		fl.plugin(0x3FF300)
		fl.uploadEEPROM(0x0, ecu_dir+"/eeprom.bin")
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	if(ecu_op == 'c'):
		crc = CRC32Reflect(0x1EDC6F41, initvalue=0xFFFFFFFF)
		print("Upload CRC lookup table...")
		for i in range(0, len(crc.table)):
			fl.writeWord(
				0x3F8000+(i*4),
				crc.table[i].to_bytes(4, "big")
			)
		fl.upload(0x3FF300,"flasher/plugin_crc.bin")
		fl.plugin(0x3FF300)
		crc_ok = True
		print("\nECU      FILE     Filename")
		print("--------------------------")
		for i in ecu_blocks:
			crc_ecu = fl.computeCRC(
				Flasher.blocks[i][2],
				Flasher.blocks[i][3]
			)
			filename = ecu_dir+"/"+Flasher.blocks[i][4]
			try:
				crc.do_file(filename)
				crc_file = crc.get() ^ 0xFFFFFFFF
			except:
				crc_file = 0
			print('%08X %08X %s' % (crc_ecu,crc_file,filename))
			if(crc_ecu != crc_file): crc_ok = False
		if(crc_ok): print("\nAll CRC are OK!\n")
		else: print("\nCRC are wrong or missing!\n")
		# Return to the flasher plugin
		fl.plugin(0x3FF200)

	bus.shutdown()
	print("Done")

