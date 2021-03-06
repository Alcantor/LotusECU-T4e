import sys, can, argparse
from lib.fileprogress import FileProgress
from lib.flasher import Flasher

# Some constants
BO_BE = 'big'

class ECUException(Exception):
	pass

class LiveTuningAccess:
	zones = [
		# K4 (29F200) has 256KB flash
		# T4 (29F400) has 512KB flash
		# T4e (MPC563) has 512KB flash
		("S0 (T4/T4e Bootloader)" , 0x000000, 0x10000, "bootldr.bin"),
		("S1 (T4e Calibration)"   , 0x010000, 0x10000, "calrom.bin"),
		("S2-S7 (T4e Program)"    , 0x020000, 0x60000, "prog.bin"),
		("RAM1 (T4e EEPROM Copy)" , 0x2F8000, 0x00800, "decram.bin"),
		("RAM2 (T4e Main RAM)"    , 0x3F8000, 0x08000, "calram.bin"),
		("S1-S6 (T4 Program)"     , 0x010000, 0x60000, "prog.bin"),
		("S7 (T4 Calibration)"    , 0x070000, 0x10000, "calrom.bin"),
		("S0-S7 (T4/T4e Full ROM)", 0x000000, 0x80000, "dump.bin"),
		# T6 (FMPC5534) has 1MB flash
		("L0-L3 (T6 Bootloader)"  , 0x000000, 0x020000, "bootldr.bin"),
		("L4-L5 (T6 Calibration)" , 0x020000, 0x020000, "calrom.bin"),
		("M0-H3 (T6 Program)"     , 0x040000, 0x0C0000, "prog.bin"),
		("L0-H3 (T6 Full ROM)"    , 0x000000, 0x100000, "dump.bin")
	]

	def __init__(self, fp):
		self.bus = None
		self.fp = fp

	def open_can(self, interface, channel, bitrate):
		if(self.bus != None): self.close_can()
		self.fp.log("Open CAN "+interface+" "+str(channel)+" @ "+str(bitrate/1000)+" kbit/s")
		self.bus = can.Bus(
			interface = interface,
			channel = channel,
			can_filters = [{
				"extended": False,
				"can_id": 0x7A0,
				"can_mask": 0x7FF
			}],
			bitrate = bitrate
		)
		# Workaround for socketcan interface.
		# The kernel filtering does not filter out the error messages.
		# So force library filtering.
		self.bus._is_filtered = False

	def close_can(self):
		if(self.bus == None): return
		self.fp.log("Close CAN")
		self.bus.shutdown()
		self.bus = None

	def read_memory(self, address, size):
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x50,
				data = address.to_bytes(4, BO_BE)
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Word failed!")
			if(msg.dlc != 4): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x51,
				data = address.to_bytes(4, BO_BE)
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Half failed!")
			if(msg.dlc != 2): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x52,
				data = address.to_bytes(4, BO_BE)
			)
			self.bus.send(msg)
			msg = self.bus.recv(timeout=1.0)
			if(msg == None): raise ECUException("ECU Read Byte failed!")
			if(msg.dlc != 1): raise ECUException("Unexpected answer!")
			data = msg.data
		elif(size < 256):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x53,
				data = address.to_bytes(4, BO_BE) + size.to_bytes(1, BO_BE)
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

	def write_memory(self, address, data, verify = False):
		size = len(data)
		if  (size == 4):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x54,
				data = address.to_bytes(4, BO_BE) + data
			)
			self.bus.send(msg)
		elif(size == 2):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x55,
				data = address.to_bytes(4, BO_BE) + data
			)
			self.bus.send(msg)
		elif(size == 1):
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x56,
				data = address.to_bytes(4, BO_BE) + data
			)
			self.bus.send(msg)
		elif(size < 256):
			offset = 0
			msg = can.Message(
				is_extended_id = False, arbitration_id = 0x57,
				data = address.to_bytes(4, BO_BE) + size.to_bytes(1, BO_BE)
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
		if(verify and data != self.read_memory(address, len(data))):
			raise ECUException("ECU Write failed!")

	def download(self, address, size, filename):
		self.fp.download(address, size, filename, self.read_memory, 128, False)

	def verify(self, address, filename):
		self.fp.verify(address, filename, self.read_memory, 128, False)

	def upload(self, address, filename):
		self.fp.upload(address, filename, self.write_memory, 128, False)

	def test(self, freeram_address):
		# Word
		self.write_memory(freeram_address, b'\xDE\xAD\xBE\xEF', True)
		# 3 Bytes
		self.write_memory(freeram_address, b'\x11\x22\x33', True)
		# Half
		self.write_memory(freeram_address, b'\xAA\x55', True)
		# Byte
		self.write_memory(freeram_address, b'\x10', True)
		# Much more
		self.write_memory(freeram_address, b'Hello world', True)

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
		choices=range(0, len(LiveTuningAccess.zones)),
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
	if(args['speed'] == 'black'):
		can_br = 500000
		canstrap_file = "flasher/canstrap-black.bin"
	else:
		can_br = 1000000
		canstrap_file = "flasher/canstrap-white.bin"
	if(args['listzone']):
		print("Zones ECU")
		for i in range(0, len(LiveTuningAccess.zones)):
			print("%i: %s" % (i, LiveTuningAccess.zones[i][0]))
		sys.exit(0)

	lta = LiveTuningAccess(FileProgress())
	lta.open_can(can_if, can_ch, can_br)
	print()

	if(ecu_op == 'dl'):
		print("Download ECU")
		for i in ecu_zones:
			lta.download(
				LiveTuningAccess.zones[i][1],
				LiveTuningAccess.zones[i][2],
				ecu_dir+"/"+LiveTuningAccess.zones[i][3]
			)

	if(ecu_op == 'v'):
		print("Verify ECU")
		for i in ecu_zones:
			lta.verify(
				LiveTuningAccess.zones[i][1],
				ecu_dir+"/"+LiveTuningAccess.zones[i][3]
			)

	if(ecu_op == 'ifp'):
		print("Inject Flash Program")
		lta.upload(0x3FF000, canstrap_file)
		lta.upload(0x3FFF00, "lib/poison.bin")
		fl = Flasher(lta.fp)
		fl.bus = lta.bus
		fl.canstrap(timeout=1.0)
		print("We have the control of the ECU!")
		# Install the flasher plugin
		fl.upload(0x3FF200, "flasher/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000, canstrap_file)
		fl.verify(0x3FF200, "flasher/plugin_flash.bin")

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		lta.test(0x3FF000)

	lta.close_can()
	print("Done")

