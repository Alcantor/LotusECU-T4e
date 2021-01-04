#!/usr/bin/python3

import datetime
from crc import CRC16Reflect

def ppc_cmplwi_opcode(register, immediate):
	opcode     = bytearray([0x28, 0x00, 0x00, 0x00])
	opcode[1] |= register & 0x1F
	opcode[2] |= (immediate >>  8) & 0xFF
	opcode[3] |= immediate & 0xFF
	return opcode

def random_date_for_crc(crcclass, crc):
	date = datetime.datetime.now()
	oneminute = datetime.timedelta(minutes=1)
	while(True):
		crcclass.reset()
		data = date.strftime("%m-%d-%Y %H:%M").encode('ascii')
		crcclass.update(data)
		if(crcclass.get() == crc):
			return data
		date -= oneminute

if __name__ == "__main__":	
	#crc = CRC16Normal(0x1021, initvalue=0x0123) # CRC for bootloader (not working yet), LUT is correct
	crc = CRC16Reflect(0x8005, initvalue=0x0000) # CRC for calibration

	crc.update(b"\x00\x00\x23\x73")
	print("TEST: "+hex(crc.get()))
	crc.update_reverse(b"\x24\x73")
	print("TEST2: "+hex(crc.get()))
	print(random_date_for_crc(crc, crc.get()))
	
	crc.reset()
	with open("dump/ALS3M0244F/calrom.bin", 'rb') as f:
		crc.update(f.read(0x3C8E))
		print("CRC: "+hex(crc.get()))
	with open("dump/ALS3M0244F/prog.bin", 'rb') as f:
		offset = f.read().find(ppc_cmplwi_opcode(0, crc.get()))
		print("CRC cmplwi offset in prog.bin: "+hex(offset))
	crc.reset()
	with open("dump/ALS3M0240J/calrom.bin", 'rb') as f:
		crc.update(f.read(0x3C8E))
		print("CRC: "+hex(crc.get()))
	with open("dump/ALS3M0240J/prog.bin", 'rb') as f:
		offset = f.read().find(ppc_cmplwi_opcode(0, crc.get()))
		print("CRC cmplwi offset in prog.bin: "+hex(offset))
	crc.reset()

