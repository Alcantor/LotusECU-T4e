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

def ECUReadMemory(address, size):
	#print("ECU Read "+str(size)+" bytes @ "+hex(address))
	if(size < 256):
		cf = struct.pack(can_header_fmt, 0x53, 5)
		cf += struct.pack(">IB3x", address, size)
	else:
		cf = struct.pack(can_header_fmt, 0x53, 6)
		cf += struct.pack(">IH2x", address, size)
	sock.send(cf)
	data = bytearray()
	while(size > 0):
		try:
			chunk_size = min(8, size);
			cf = sock.recv(can_frame_size)
			data += cf[can_header_size:can_header_size+chunk_size]
			size -= chunk_size
		except socket.timeout:
			return None
	return data

def ECUWriteMemory(address, data, verify):
	if(len(data) < 1 or 4 < len(data)):
		return False
	#print("ECU Write "+str(data)+" @ "+hex(address))
	if  (len(data) == 3):
		return ECUWriteMemory(address, data[:2], verify) \
			and ECUWriteMemory(address+2, data[2:], verify)
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
	if(verify == False): return True
	return data == ECUReadMemory(address, len(data))
	
def ECUDownload(address, size, filename):
	print("ECU Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
	f = open(filename, "wb")
	while(size > 0):
		chunk_size = min(128, size);
		chunk = ECUReadMemory(address, chunk_size)
		if(chunk == None):
			print("ECU Download error. Abording")
			return False
		if(f.write(chunk) != chunk_size):
			print("ECU File writing error. Abording!")
			return False
		print(".", end="", flush=True) # One dot every 128 Bytes
		address += chunk_size
		size -= chunk_size
	f.close()
	print()
	return True
	
def ECUVerify(address, data):
	offset = 0
	size = len(data)
	print("ECU Verify "+str(size)+" bytes @ "+hex(address))
	while(size > 0):
		chunk_size = min(128, size);
		chunk = ECUReadMemory(address, chunk_size)
		if(chunk == None):
			print("ECU Download error. Abording")
			return False
		if(data[offset:offset+chunk_size] != chunk):
			print("ECU Verify error. Abording")
			return False
		print(".", end="", flush=True) # One dot every 128 Bytes
		address += chunk_size
		offset += chunk_size
		size -= chunk_size
	print()
	return True

def ECUErase(blockid):
	UC3FMCR_ADDR = 0x2FC800 # Configuration Register
	UC3FCTL_ADDR = 0x2FC808 # High Voltage Control Register
	flash_addr  = 0x010000 * blockid # Block base address
	flash_bmask = 0x80 >> blockid # Block mask
	print("Erase block "+str(blockid))
	# PROTECT[M]=0
	r = ECUWriteMemory(UC3FMCR_ADDR + 3, bytes([0xFF & ~flash_bmask]), True)
	if(r == None): return False
	# BLOCK[M]=1
	r = ECUWriteMemory(UC3FCTL_ADDR + 2, bytes([flash_bmask]), True)
	if(r == None): return False
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x06', False) # PE=1 and SES=1
	ECUWriteMemory(flash_addr, b'\xFF\xFF\xFF\xFF', False) # Interlock
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x07', False) # EHV=1
	while(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
	pegood = True if(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x00', False) # PE=0 SES=0 EHV=0
	return pegood
	
def ECUProgram(blockid, data):
	UC3FMCR_ADDR = 0x2FC800 # Configuration Register
	UC3FCTL_ADDR = 0x2FC808 # High Voltage Control Register
	flash_addr  = 0x010000 * blockid # Block base address
	flash_bmask = 0x80 >> blockid # Block mask
	if(len(data) % 4 > 0):
		print("WARNING: Data has been padded with 0xFF")
		data += b'\xFF\xFF\xFF\xFF'[(len(data)%4):]
	if(len(data) > 0x010000):
		print("ERROR: Too much data")
		return False
	print("Write block "+str(blockid))
	# PROTECT[M]=0
	r = ECUWriteMemory(UC3FMCR_ADDR + 3, bytes([0xFF & ~flash_bmask]), True)
	if(r == None): return False
	# BLOCK[M]=1
	r = ECUWriteMemory(UC3FCTL_ADDR + 2, bytes([flash_bmask]), True)
	if(r == None): return False
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x02', False) # PE=0 and SES=1
	for i in range(0, len(data), 4):
		ECUWriteMemory(flash_addr+i, data[i:i+4], False) # Interlock
		ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x03', False) # EHV=1
		while(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x80): pass # Wait on HVS=0
		pegood = True if(ECUReadMemory(UC3FCTL_ADDR + 0, 1)[0] & 0x40) else False
		ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x02', False) # EHV=0
		if(not pegood): break
		if(i % 128 == 0): print(".", end="", flush=True) # One dot every 128 Bytes
	ECUWriteMemory(UC3FCTL_ADDR + 3, b'\x00', False) # SES=1
	print()
	return pegood
	
def ECUUpload(blockid, filename):
	f = open(filename, "rb")
	data = f.read()
	f.close()
	address = 0x010000 * blockid
	print("ECU Upload "+str(len(data))+" bytes @ block"+hex(address)+" from "+filename)
	if(not ECUErase(blockid)):
		print("Erase failed!")
		return False
	if(not ECUProgram(blockid, data)):
		print("Program failed!")
		return False
	if(not ECUVerify(address, data)):
		print("Verify failed!")
		return False
	return True
	
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
	help="The action to do: dl -> Download like Cybernet, dlc -> Download only the calibration, dlf -> Dowload like Obeisance, upc -> Upload the calibration",
	choices=["dl", "dlc", "dlf", "upc"]
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

if(ecu_op == 'dl'):
	print("\nDownload ECU (Obeisance)")
	ECUDownload(0x000000, 0x80000, ecu_dir+"/dump.bin")

if(ecu_op == 'upc'):
	# DANGEROUS never tested!
	print("\nUpload ECU Calibration")
	ECUUpload(1, ecu_dir+"/calrom.bin")

print("Done")

