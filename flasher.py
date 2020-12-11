#!/usr/bin/python3

# Emulation of can bus if needed
# sudo ip link add dev can0 type vcan

import os, sys, socket, struct, argparse

CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000

CAN_SFF_MASK = 0x000007FF
CAN_EFF_MASK = 0x1FFFFFFF
CAN_ERR_MASK = 0x1FFFFFFF

CAN_HDR_FRMT = "=IB3x"
CAN_HDR_SIZE = struct.calcsize(CAN_HDR_FRMT);
CAN_FRA_SIZE = CAN_HDR_SIZE + 8;

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

	def openCAN(self, can_if):
		self.log("Open "+can_if+" @ 1 Mbit/s")
		os.system("ip link set "+can_if+" down")
		os.system("ip link set "+can_if+" up type can bitrate 1000000 restart-ms 50 loopback off")
		self.sock = socket.socket(socket.AF_CAN,socket.SOCK_RAW,socket.CAN_RAW);
		self.sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, \
			struct.pack("=II",0x7A0, CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))
		self.sock.bind((can_if,))
		self.sock.settimeout(1.0)

	def echo(self, data):
		#self.log("Flasher Echo "+data)
		echo_len = len(data)
		if(echo_len > 7):
			raise FlasherException("Echo too big")
		try:
			cmd = 0x00
			fmt = CAN_HDR_FRMT+"B%ds%dx" % (echo_len, 7 - echo_len)
			cf = struct.pack(fmt, 0x60, echo_len+1, cmd, data)
			self.sock.send(cf)
			cf = self.sock.recv(CAN_FRA_SIZE)
			id, dlc, rcmd, rdata = struct.unpack(fmt, cf)
			if(dlc != echo_len+1 or rcmd != cmd or rdata != data):
				FlasherException("Unexpected answer!")
		except socket.timeout:
			raise FlasherException("Flasher Echo failed!") from None

	def readWord(self, address):
		#self.log("Flasher Read Word @ "+hex(address))
		try:
			cmd = 0x01
			cf = struct.pack(CAN_HDR_FRMT, 0x60, 4)
			cf += struct.pack(">I4x", (cmd<<24) | address)
			self.sock.send(cf)
			cf = self.sock.recv(CAN_FRA_SIZE)
			id, dlc, rcmd, data = struct.unpack(CAN_HDR_FRMT+"B4s3x", cf)
			if(dlc != 5 or rcmd != cmd):
				FlasherException("Unexpected answer!")
			return data
		except socket.timeout:
			raise FlasherException("Flasher Read Word failed!") from None

	def writeWord(self, address, data):
		#self.log("Flasher Write Word @ "+hex(address))
		try:
			cmd = 0x02
			cf = struct.pack(CAN_HDR_FRMT, 0x60, 8)
			cf += struct.pack(">I4s", (cmd<<24) | address, data)
			self.sock.send(cf)
			cf = self.sock.recv(CAN_FRA_SIZE)
			id, dlc, rcmd = struct.unpack(CAN_HDR_FRMT+"B7x", cf)
			if(dlc != 1 or rcmd != cmd):
				FlasherException("Unexpected answer!")
		except socket.timeout:
			raise FlasherException("Flasher Write Word failed!") from None

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
					raise ECUException("Flasher Verify failed!")
				self.progress() # One dot every 4 Bytes
				address += 4
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
		self.log("Unimplemented")
		
	def test(self, freeram_address):
		self.echo(b'Hi ;-)')
		test = b'\xDE\xAD\xBE\xEF'
		self.writeWord(freeram_address, test)
		if(test != self.readWord(freeram_address)):
			raise ECUException("Word readback failed!")
		self.upload(freeram_address, "injection/deadloop.bin")
		self.verify(freeram_address, "injection/deadloop.bin")

if __name__ == "__main__":
	print("Stupid flasher for Lotus T4e ECU\n")
	ap = argparse.ArgumentParser()
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
			"vfp -> Verify Flasher Program, "
			"p -> Verify Flash Program, "
			"t -> Tests",
		choices=["dl", "v", "vfp", "t"],
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
	can_if = args['device']
	ecu_op = args['operation']
	ecu_dir = args['directory']
	ecu_blocks = args['block']
	if(args['listblock']):
		print("Blocks ECU")
		for i in range(0, len(Flasher.blocks)):
			print("%i: %s" % (i, Flasher.blocks[i][0]))
		sys.exit(0)

	fl = Flasher();
	fl.openCAN(can_if)
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

	if(ecu_op == 'vfp'):
		print("Verify Flasher Program")
		fl.verify(0x3FF000,"injection/flasher.bin")

	if(ecu_op == 'p'):
		print("Program ECU")
		for i in ecu_blocks:
			fl.program(
				Flasher.blocks[i][1],
				Flasher.blocks[i][2],
				ecu_dir+"/"+Flasher.blocks[i][4]
			)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		fl.test(0x3F8000)

	print("Done")

