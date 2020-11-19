#!/usr/bin/python3

# Emulation of can bus if needed
# sudo ip link add dev can0 type vcan

import os, sys, socket, struct

CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000

CAN_SFF_MASK = 0x000007FF
CAN_EFF_MASK = 0x1FFFFFFF
CAN_ERR_MASK = 0x1FFFFFFF

can_if = "can0"
can_header_fmt = "=IB3x"
can_header_size = struct.calcsize(can_header_fmt);
can_frame_size = can_header_size + 8;
ecu_req_fmt = ">IB3x"
ecu_resp_fmt = "8B"

def ECUReadMemory(address, size):
	if(size > 255):
		return None
	#print("ECU Read "+str(size)+" bytes @ "+hex(address))
	cf = struct.pack(can_header_fmt, 0x53, 5) + struct.pack(ecu_req_fmt, address, size)
	sock.send(cf)
	n_frames_expected = int(size / 8);
	last_frame_size = size % 8;
	response = bytearray()
	for i in range(0, n_frames_expected):
		#print("ECU Wait reply "+str(i)+" of "+str(n_frames_expected))
		try:		
			cf = sock.recv(can_frame_size)
			response += cf[can_header_size:can_frame_size]
		except socket.timeout:
			print("ECU Timeout!")
			return None
	if(last_frame_size > 0):
		#print("ECU Wait last reply "+str(last_frame_size)+" bytes remaining")
		try:		
			cf = sock.recv(can_frame_size)
			response += cf[can_header_size:can_header_size+last_frame_size]
		except socket.timeout:
			print("ECU Timeout!")
			return None
	return response

def ECUDownload(address, size, filename):
	print("ECU Download "+str(size)+" bytes @ "+hex(address)+" into "+filename)
	f = open(filename, "wb")
	while(size > 0):
		chunk_size = min(255, size);
		chunk = ECUReadMemory(address, chunk_size)
		if(chunk == None):
			print("ECU Download error. Abording")
			return False
		address += chunk_size
		size -= chunk_size
		if(f.write(chunk) != chunk_size):
			print("ECU File writing error. Abording!")
			return False
	f.close()
	return True

print("Stupid dumper for Lotus T4e ECU\n")

print("\nConfigure "+can_if+" @ 1 Mbit/s")
os.system("ip link set "+can_if+" down")
r = os.system("ip link set "+can_if+" up type can bitrate 1000000 restart-ms 50 loopback off")
if(r != 0):
	sys.exit(r)

print("\nOpen can0")
sock = socket.socket(socket.AF_CAN,socket.SOCK_RAW,socket.CAN_RAW);
sock.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, \
	struct.pack("=II",0x7A0, CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG)) 
sock.bind((can_if,))
sock.settimeout(1.0)

print("\nDownload ECU")
# Section dump (Like Cybernet)
ECUDownload(0x00000000, 0x10000, "bootldr.bin")
ECUDownload(0x00010000, 0x10000, "calrom.bin")
ECUDownload(0x00020000, 0x60000, "prog.bin")
ECUDownload(0x002F8000, 0x00800, "decram.bin")
ECUDownload(0x003F8000, 0x08000, "calram.bin")

# Flat dump (Like Obeisance)
ECUDownload(0x00000000, 0x80000, "dump.bin")

print("Done")

