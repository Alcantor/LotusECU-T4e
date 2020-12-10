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

	def openCAN(self, can_if):
		self.log("Open "+can_if+" @ 1 Mbit/s")
		os.system("ip link set "+can_if+" down")
		os.system("ip link set "+can_if+" up type can bitrate 1000000 restart-ms 50 loopback off")
		self.sock = socket.socket(socket.AF_CAN,socket.SOCK_RAW,socket.CAN_RAW);
		self.sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, \
			struct.pack("=II",0x7A0, CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))
		self.sock.bind((can_if,))
		self.sock.settimeout(1.0)

	def readMemory(self, address, size):
		#self.log("ECU Read "+str(size)+" bytes @ "+hex(address))
		try:
			if  (size == 4):
				cf = struct.pack(CAN_HDR_FRMT, 0x50, 4)
				cf += struct.pack(">I4x", address)
				self.sock.send(cf)
				cf = self.sock.recv(CAN_FRA_SIZE)
				id, dlc, data = struct.unpack(CAN_HDR_FRMT+"4s4x", cf)
				if(dlc != 4): ECUException("Unexpected answer!")
			elif(size == 2):
				cf = struct.pack(CAN_HDR_FRMT, 0x51, 4)
				cf += struct.pack(">I4x", address)
				self.sock.send(cf)
				cf = self.sock.recv(CAN_FRA_SIZE)
				id, dlc, data = struct.unpack(CAN_HDR_FRMT+"2s6x", cf)
				if(dlc != 2): ECUException("Unexpected answer!")
			elif(size == 1):
				cf = struct.pack(CAN_HDR_FRMT, 0x52, 4)
				cf += struct.pack(">I4x", address)
				self.sock.send(cf)
				cf = self.sock.recv(CAN_FRA_SIZE)
				id, dlc, data = struct.unpack(CAN_HDR_FRMT+"1s7x", cf)
				if(dlc != 1): ECUException("Unexpected answer!")
			elif(size < 256):
				cf = struct.pack(CAN_HDR_FRMT, 0x53, 5)
				cf += struct.pack(">IB3x", address, size)
				self.sock.send(cf)
				data = bytearray()
				while(size > 0):
					chunk_size = min(8, size);
					cf = self.sock.recv(CAN_FRA_SIZE)
					id, dlc, chunk = struct.unpack(CAN_HDR_FRMT+"%ds%dx" \
						% (chunk_size, 8 - chunk_size), cf)
					if(dlc != chunk_size): ECUException("Unexpected answer!")
					data += chunk
					size -= chunk_size
			else:
				raise ECUException("ECU Read too much bytes!")
			return data
		except socket.timeout:
			raise ECUException("ECU Read failed!") from None

	def writeMemory(self, address, data, verify = True):
		#self.log("ECU Write "+str(data)+" @ "+hex(address))
		if  (len(data) == 4):
			cf = struct.pack(CAN_HDR_FRMT, 0x54, 8)
			cf += struct.pack(">I4s0x", address, data)
			self.sock.send(cf)
		elif(len(data) == 2):
			cf = struct.pack(CAN_HDR_FRMT, 0x55, 6)
			cf += struct.pack(">I2s2x", address, data)
			self.sock.send(cf)
		elif(len(data) == 1):
			cf = struct.pack(CAN_HDR_FRMT, 0x56, 5)
			cf += struct.pack(">I1s3x", address, data)
			self.sock.send(cf)
		elif(len(data) < 256):
			size = len(data)
			offset = 0
			cf = struct.pack(CAN_HDR_FRMT, 0x57, 5)
			cf += struct.pack(">IB3x", address, size)
			self.sock.send(cf)
			while(size > 0):
				chunk_size = min(8, size);
				cf = struct.pack(CAN_HDR_FRMT+"%ds%dx" % (chunk_size, 8 - chunk_size), \
					0x57, chunk_size, data[offset:offset+chunk_size])
				self.sock.send(cf)
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
					raise ECUException("ECU Verify failed!")
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
		value = self.readMemory(stackblr_address, 4)
		self.log("Previous return address 0x"+value.hex())
		self.writeMemory(stackblr_address, struct.pack(">I", freeram_address), False)
		try:
			cf = self.sock.recv(CAN_FRA_SIZE)
			id, dlc, data = struct.unpack(CAN_HDR_FRMT+"6s2x", cf)
			if(dlc != 6 or data != b'Hello!'):
				raise ECUException("Unexpected answer!")
			else:
				self.log("We have the control of the ECU!")
		except socket.timeout:
			raise ECUException("Injection failed!") from None

		
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
		"-d",
		"--device",
		required=False,
		help="The CAN-Bus device to use.",
		default="can0"
	)
	ap.add_argument(
		"-o",
		"--operation",
		required=False,
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
		help="Dump directory",
		default="."
	)
	ap.add_argument(
		"-z",
		"--zone",
		type=int,
		required=False,
		help="Specify a zone",
		choices=range(0, len(ECU_T4E.zones)),
		default=None
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
	can_if = args['device']
	ecu_op = args['operation']
	ecu_dir = args['directory']
	if(args['zone'] == None):
		ecu_zones = range(0, 5)
	else:
		ecu_zones = (args['zone'],)
	if(args['listzone']):
		print("Zones ECU")
		for i in range(0, len(ECU_T4E.zones)):
			print("%i: %s" % (i, ECU_T4E.zones[i][0]))
		sys.exit(0)

	t4e = ECU_T4E();
	t4e.openCAN(can_if)
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
		t4e.inject(0x3FE748, "injection/deadloop.bin", 0x3FFFDC)
		#t4e.inject(0x3FE748, "injection/flasher.bin", 0x3FFFDC)

	if(ecu_op == 't'):
		print("Test ECU Read/Write")
		t4e.test(0x3FE748)

	print("Done")

