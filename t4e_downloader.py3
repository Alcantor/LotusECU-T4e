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

can_header_fmt = "=IB3x"
can_header_size = struct.calcsize(can_header_fmt);
can_frame_size = can_header_size + 8;

UC3FMCR_ADDR = 0x2FC800 # Configuration Register
UC3FCTL_ADDR = 0x2FC808 # High Voltage Control Register

class ECUException(Exception):
    pass

def ECUReadMemory(address, size):
	#print("ECU Read "+str(size)+" bytes @ "+hex(address))
	if(size < 256):
		cf = struct.pack(can_header_fmt, 0x53, 5)
		cf += struct.pack(">IB3x", address, size)
	elif(size < 65536):
		cf = struct.pack(can_header_fmt, 0x53, 6)
		cf += struct.pack(">IH2x", address, size)
	else:
		raise ECUException("ECU Read too much bytes!")
	sock.send(cf)
	data = bytearray()
	while(size > 0):
		try:
			chunk_size = min(8, size);
			cf = sock.recv(can_frame_size)
			data += cf[can_header_size:can_header_size+chunk_size]
			size -= chunk_size
		except socket.timeout:
			raise ECUException("ECU Read failed!") from None
	return data

def ECUWriteMemory(address, data, verify = True):
	if(len(data) < 1 or 4 < len(data)):
		raise ECUException("ECU Write too much bytes!")
	#print("ECU Write "+str(data)+" @ "+hex(address))
	if  (len(data) == 3):
		ECUWriteMemory(address, data[:2], verify)
		ECUWriteMemory(address+2, data[2:], verify)
	elif(len(data) == 4):
		cf = struct.pack(can_header_fmt, 0x54, 8)
		cf += struct.pack(">I4s", address, data)
	elif(len(data) == 2):
		cf = struct.pack(can_header_fmt, 0x55, 6)
		cf += struct.pack(">I2s2x", address, data)
	elif(len(data) == 1):
		cf = struct.pack(can_header_fmt, 0x56, 5)
		cf += struct.pack(">I1s3x", address, data)
	sock.send(cf)
	if(verify and data != ECUReadMemory(address, len(data))):
		raise ECUException("ECU Write failed!")
	
def ECUDownload(address, size, filename):
	print("ECU Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
	with open(filename,'wb') as f:
		while(size > 0):
			chunk_size = min(128, size);
			chunk = ECUReadMemory(address, chunk_size)
			f.write(chunk)
			print(".", end="", flush=True) # One dot every 128 Bytes
			address += chunk_size
			size -= chunk_size
		print()
	
def ECUVerify(address, filename):
	print("ECU Verify @ "+hex(address)+" from "+filename)
	with open(filename,'rb') as f:
		while(True):
			f_chunk = f.read(128)
			chunk_size = len(f_chunk)
			if(chunk_size == 0): break # EOF
			chunk = ECUReadMemory(address, chunk_size)
			if(f_chunk != chunk):
				raise ECUException("ECU Verify failed!")
			print(".", end="", flush=True) # One dot every 128 Bytes
			address += chunk_size
		print()

def ECUUnlock(blockid):
	flash_bmask = 0x80 >> blockid # Block mask
	flash_bmask_inv = 0xFF & ~flash_bmask; # Block mask inverted
	print("ECU Unlock block "+str(blockid))
	# PROTECT[M]=0 and BLOCK[M]=1
	ECUWriteMemory(UC3FMCR_ADDR + 3, bytes([flash_bmask_inv]))
	ECUWriteMemory(UC3FCTL_ADDR + 2, bytes([flash_bmask]))

def ECULock():
	print("ECU Lock block")
	# PROTECT[all]=1 and BLOCK[all]=0
	ECUWriteMemory(UC3FMCR_ADDR + 3, b'\xFF')
	ECUWriteMemory(UC3FCTL_ADDR + 2, b'\x00')

def ECUErase(blockid):
	address  = 0x010000 * blockid # Block base address
	print("ECU Erase block "+str(blockid))
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x06', False) # PE=1 and SES=1
	ECUWriteMemory(address, b'\xFF\xFF\xFF\xFF', False) # Interlock
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x07', False) # EHV=1
	while(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
	pegood = True if(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x00', False) # PE=0 SES=0 EHV=0
	if(not pegood): raise ECUException("ECU Erase failed!")
	
def ECUProgram(blockid, filename):
	address  = 0x010000 * blockid # Block base address
	print("ECU Program block "+str(blockid)+" from "+filename)
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x02', False) # PE=0 and SES=1
	with open(filename,'rb') as f:
		while(True):
			chunk = f.read(4)
			chunk_size = len(chunk)
			if(chunk_size == 0): break # EOF
			ECUWriteMemory(address, chunk, False) # Interlock
			ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x03', False) # EHV=1
			while(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
			pegood = True if(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
			ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x02', False) # EHV=0
			if(not pegood): break
			if(address % 128 == 0): print(".", end="", flush=True) # One dot every 128 Bytes
			address += chunk_size
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x00', False) # SES=0
	if(not pegood): raise ECUException("ECU Program failed!")
	print()
	
def ECUUpload(blockid, filename):
	ECUUnlock(blockid)
	ECUErase(blockid)
	ECUProgram(blockid, filename)
	ECULock()
	ECUVerify(0x010000 * blockid, filename)
	
print("Stupid dumper for Lotus T4e ECU\n")

# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
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
	help="The action to do: dl -> Download like Cybernet, dlc -> Download only the calibration, dlf -> Dowload like Obeisance, upc -> Upload the calibration, vc -> Verify the calibration",
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

print("\nConfigure "+can_if+" @ 1 Mbit/s")
os.system("ip link set "+can_if+" down")
os.system("ip link set "+can_if+" up type can bitrate 1000000 restart-ms 50 loopback off")

print("\nOpen "+can_if)
sock = socket.socket(socket.AF_CAN,socket.SOCK_RAW,socket.CAN_RAW);
sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, \
	struct.pack("=II",0x7A0, CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG)) 
sock.bind((can_if,))
sock.settimeout(1.0)

if(ecu_op == 'dl'):
	print("\nDownload ECU (Cybernet)")
	ECUDownload(0x000000, 0x10000, ecu_dir+"/bootldr.bin")
	ECUDownload(0x010000, 0x10000, ecu_dir+"/calrom.bin")
	ECUDownload(0x020000, 0x60000, ecu_dir+"/prog.bin")
	ECUDownload(0x2F8000, 0x00800, ecu_dir+"/decram.bin")
	ECUDownload(0x3F8000, 0x08000, ecu_dir+"/calram.bin")
	
if(ecu_op == 'dlc'):
	print("\nDownload ECU (Cybernet) - Only Calibration")
	ECUDownload(0x010000, 0x10000, ecu_dir+"/calrom.bin")

if(ecu_op == 'dlf'):
	print("\nDownload ECU (Obeisance)")
	ECUDownload(0x000000, 0x80000, ecu_dir+"/dump.bin")

if(ecu_op == 'upc'):
	# DANGEROUS never tested!
	print("\nUpload ECU Calibration")
	ECUUpload(1, ecu_dir+"/calrom.bin")

if(ecu_op == 'vc'):
	print("\nVerify ECU Calibration")
	ECUVerify(0x010000, ecu_dir+"/calrom.bin")

print("Done")

