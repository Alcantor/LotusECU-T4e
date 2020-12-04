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

UC3FMCR_ADDR = 0x2FC800 # Configuration Register
UC3FCTL_ADDR = 0x2FC808 # High Voltage Control Register

class ECUException(Exception):
	pass

class ECU_T4E:
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
		self.log("Configure "+can_if+" @ 1 Mbit/s")
		os.system("ip link set "+can_if+" down")
		os.system("ip link set "+can_if+" up type can bitrate 1000000 restart-ms 50 loopback off")

		self.log("Open "+can_if)
		self.sock = socket.socket(socket.AF_CAN,socket.SOCK_RAW,socket.CAN_RAW);
		self.sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, \
			struct.pack("=II",0x7A0, CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))
		self.sock.bind((can_if,))
		self.sock.settimeout(1.0)

	def readMemory(self, address, size):
		#self.log("ECU Read "+str(size)+" bytes @ "+hex(address))
		if(size < 256):
			cf = struct.pack(CAN_HDR_FRMT, 0x53, 5)
			cf += struct.pack(">IB3x", address, size)
		elif(size < 65536):
			cf = struct.pack(CAN_HDR_FRMT, 0x53, 6)
			cf += struct.pack(">IH2x", address, size)
		else:
			raise ECUException("ECU Read too much bytes!")
		self.sock.send(cf)
		data = bytearray()
		while(size > 0):
			try:
				chunk_size = min(8, size);
				cf = self.sock.recv(CAN_FRA_SIZE)
				data += cf[CAN_HDR_SIZE:CAN_HDR_SIZE+chunk_size]
				size -= chunk_size
			except socket.timeout:
				raise ECUException("ECU Read failed!") from None
		return data

	def writeMemory(self, address, data, verify = True):
		if(len(data) < 1 or 4 < len(data)):
			raise ECUException("ECU Write too much bytes!")
		#self.log("ECU Write "+str(data)+" @ "+hex(address))
		if  (len(data) == 3):
			self.writeMemory(address, data[:2], verify)
			self.writeMemory(address+2, data[2:], verify)
		elif(len(data) == 4):
			cf = struct.pack(CAN_HDR_FRMT, 0x54, 8)
			cf += struct.pack(">I4s", address, data)
		elif(len(data) == 2):
			cf = struct.pack(CAN_HDR_FRMT, 0x55, 6)
			cf += struct.pack(">I2s2x", address, data)
		elif(len(data) == 1):
			cf = struct.pack(CAN_HDR_FRMT, 0x56, 5)
			cf += struct.pack(">I1s3x", address, data)
		self.sock.send(cf)
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
		self.log("ECU Verify @ "+hex(address)+" from "+filename)
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

	def unlock(self, blockid):
		flash_bmask = 0x80 >> blockid # Block mask
		flash_bmask_inv = 0xFF & ~flash_bmask; # Block mask inverted
		self.log("ECU Unlock block "+str(blockid))
		# PROTECT[M]=0 and BLOCK[M]=1
		self.writeMemory(UC3FMCR_ADDR + 3, bytes([flash_bmask_inv]))
		self.writeMemory(UC3FCTL_ADDR + 2, bytes([flash_bmask]))

	def lock(self):
		self.log("ECU Lock block")
		# PROTECT[all]=1 and BLOCK[all]=0
		self.writeMemory(UC3FMCR_ADDR + 3, b'\xFF')
		self.writeMemory(UC3FCTL_ADDR + 2, b'\x00')

	def erase(self, blockid):
		address  = 0x010000 * blockid # Block base address
		self.log("ECU Erase block "+str(blockid))
		self.writeMemory(UC3FCTL_ADDR + 3, b'\x06', False) # PE=1 and SES=1
		self.writeMemory(address, b'\xFF\xFF\xFF\xFF', False) # Interlock
		self.writeMemory(UC3FCTL_ADDR + 3, b'\x07', False) # EHV=1
		while(self.readMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
		pegood = True if(self.readMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
		self.writeMemory(UC3FCTL_ADDR + 3, b'\x00', False) # PE=0 SES=0 EHV=0
		if(not pegood): raise ECUException("ECU Erase failed!")

	def program(self, blockid, filename):
		address  = 0x010000 * blockid # Block base address
		self.log("ECU Program block "+str(blockid)+" from "+filename)
		self.writeMemory(UC3FCTL_ADDR + 3, b'\x02', False) # PE=0 and SES=1
		with open(filename,'rb') as f:
			while(True):
				chunk = f.read(4)
				chunk_size = len(chunk)
				if(chunk_size == 0): break # EOF
				self.writeMemory(address, chunk, False) # Interlock
				self.writeMemory(UC3FCTL_ADDR + 3, b'\x03', False) # EHV=1
				while(self.readMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
				pegood = True if(self.readMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
				self.writeMemory(UC3FCTL_ADDR + 3, b'\x02', False) # EHV=0
				if(not pegood): break
				if(address % 128 == 0): self.progress() # One dot every 128 Bytes
				address += chunk_size
			self.writeMemory(UC3FCTL_ADDR + 3, b'\x00', False) # SES=0
			if(not pegood): raise ECUException("ECU Program failed!")
			self.progress_end()

	def upload(self, blockid, filename):
		self.unlock(blockid)
		self.erase(blockid)
		self.program(blockid, filename)
		self.lock()
		self.verify(0x010000 * blockid, filename)

if __name__ == "__main__":
	print("Stupid dumper for Lotus T4e ECU\n")
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"-d",
		"--device",
		required=True,
		help="The CAN-Bus device to use."
	)
	ap.add_argument(
		"-o",
		"--operation",
		required=True,
		help=
			"The action to do:"
			"dl -> Download like Cybernet,"
			"dlc -> Download only the calibration,"
			"dlf -> Dowload like Obeisance,"
			"upc -> Upload the calibration,"
			"vc -> Verify the calibration",
		choices=["dl", "dlc", "dlf", "upc", "vc"]
	)
	ap.add_argument(
		"-D",
		"--directory",
		required=False,
		help="Dump directory",
		default="."
	)
	args = vars(ap.parse_args())
	can_if = args['device']
	ecu_op = args['operation']
	ecu_dir = args['directory']

	t4e = ECU_T4E();
	t4e.openCAN(can_if)

	if(ecu_op == 'dl'):
		print("\nDownload ECU (Cybernet)")
		t4e.download(0x000000, 0x10000, ecu_dir+"/bootldr.bin")
		t4e.download(0x010000, 0x10000, ecu_dir+"/calrom.bin")
		t4e.download(0x020000, 0x60000, ecu_dir+"/prog.bin")
		t4e.download(0x2F8000, 0x00800, ecu_dir+"/decram.bin")
		t4e.download(0x3F8000, 0x08000, ecu_dir+"/calram.bin")
		
	if(ecu_op == 'dlc'):
		print("\nDownload ECU (Cybernet) - Only Calibration")
		t4e.download(0x010000, 0x10000, ecu_dir+"/calrom.bin")

	if(ecu_op == 'dlf'):
		print("\nDownload ECU (Obeisance)")
		t4e.download(0x000000, 0x80000, ecu_dir+"/dump.bin")

	if(ecu_op == 'upc'):
		# DANGEROUS never tested!
		print("\nUpload ECU Calibration")
		t4e.upload(1, ecu_dir+"/calrom.bin")

	if(ecu_op == 'vc'):
		print("\nVerify ECU Calibration")
		t4e.verify(0x010000, ecu_dir+"/calrom.bin")

	print("Done")

