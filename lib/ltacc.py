import sys, can, argparse
from lib.fileprogress import FileProgress
from lib.flasher import Flasher

# Some constants
BO_BE = 'big'

class ECUException(Exception):
	pass

class LiveTuningAccess:
	zones = [
		# T4e (MPC563) has 512KB flash, 32KB RAM, 2KB DECRAM
		("T4e: S0 (Bootloader)"  , 0x00000000, 0x010000, "bootldr.bin"),
		("T4e: S1 (Calibration)" , 0x00010000, 0x010000, "calrom.bin"),
		("T4e: S2-S7 (Program)"  , 0x00020000, 0x060000, "prog.bin"),
		("T4e: RAM1 (Learned)"   , 0x002F8000, 0x000800, "decram.bin"),
		("T4e: RAM2 (Main RAM)"  , 0x003F8000, 0x008000, "calram.bin"),
		("T4e: S0-S7 (Full ROM)" , 0x00000000, 0x080000, "dump.bin"),
		# K4 (29F200) has 256KB flash, 128KB RAM
		("K4: S0-S3 (Bootloader)", 0x00000000, 0x010000, "bootldr.bin"),
		("K4: S2 (Learned)"      , 0x00006000, 0x002000, "decram.bin"),
		("K4: S4-S5 (Program)"   , 0x00010000, 0x020000, "prog.bin"),
		("K4: S6 (Calibration)"  , 0x00030000, 0x010000, "calrom.bin"),
		("K4: RAM (Main RAM)"    , 0x00080000, 0x020000, "calram.bin"),
		("K4: S0-S6 (Full ROM)"  , 0x00000000, 0x040000, "dump.bin"),
		# T4 (29F400) has 512KB flash, 128KB RAM
		("T4: S0-S3 (Bootloader)", 0x00000000, 0x010000, "bootldr.bin"),
		("T4: S2 (Learned)"      , 0x00006000, 0x002000, "decram.bin"),
		("T4: S4-S9 (Program)"   , 0x00010000, 0x060000, "prog.bin"),
		("T4: S10 (Calibration)" , 0x00070000, 0x010000, "calrom.bin"),
		("T4: RAM (Main RAM)"    , 0x00080000, 0x020000, "calram.bin"),
		("T4: S0-S10 (Full ROM)" , 0x00000000, 0x080000, "dump.bin"),
		# T6 (MPC5534) has 2MB flash, 64KB RAM
		("T6: L0-L1 (Bootloader)", 0x00000000, 0x010000, "bootldr.bin"),
		("T6: L2 (Learned)"      , 0x00010000, 0x00C000, "decram.bin"),
		("T6: L3 (Coding)"       , 0x0001C000, 0x004000, "coding.bin"),
		("T6: L4 (Calibration)"  , 0x00020000, 0x010000, "calrom.bin"),
		("T6: M0-H3 (Program)"   , 0x00040000, 0x0C0000, "prog.bin"),
		("T6: RAM (Main RAM)"    , 0x40000000, 0x010000, "calram.bin"),
		("T6: L0-H11 (Full ROM)" , 0x00000000, 0x200000, "dump.bin")
	]

	def __init__(self, fp):
		self.bus = None
		self.fp = fp

	def open_can(self, interface, channel, bitrate):
		if(self.bus != None): self.close_can()
		self.fp.log("Open CAN "+interface+" "+channel+" @ "+str(bitrate//1000)+" kbit/s")
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

	def watch(self, address, filename, size, copy, verify, ui_cb=lambda:None):
		write_fnct = lambda a,d: self.write_memory(a,d,verify)
		if(copy):
			self.fp.upload(address, filename, write_fnct, 128, False, 0, size)
		self.fp.watch(address, filename, write_fnct, 0, size, ui_cb)

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
		canstrap_file = "flasher/t4e/canstrap-black.bin"
	else:
		can_br = 1000000
		canstrap_file = "flasher/t4e/canstrap-white.bin"
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
		fl.canstrap(timeout=1)
		print("We have the control of the ECU!")
		# Install the flasher plugin
		fl.upload(0x3FF200, "flasher/t4e/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000, canstrap_file)
		fl.verify(0x3FF200, "flasher/t4e/plugin_flash.bin")

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		lta.test(0x3FF000)

	lta.close_can()
	print("Done")

