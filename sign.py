#!/usr/bin/python3

import datetime
from crc import CRC16Reflect

charset = "ISO-8859-15"

def ppc_cmplwi_opcode(register, immediate):
	opcode     = bytearray([0x28, 0x00, 0x00, 0x00])
	opcode[1] |= register & 0x1F
	opcode[2] |= (immediate >>  8) & 0xFF
	opcode[3] |= immediate & 0xFF
	return opcode

def random_date_for_crc(crcclass, crc):
	date = datetime.datetime.now()
	onesecond= datetime.timedelta(seconds=1)
	while(True):
		crcclass.reset()
		data = date.strftime("%m-%d-%Y %H:%M:%S").encode(charset)
		crcclass.update(data)
		if(crcclass.get() == crc):
			return data
		date -= onesecond

def sign_calrom(ori_file, inp_file, out_file, name_sign):
	crc = CRC16Reflect(0x8005, initvalue=0x0000) # CRC for calibration
	name_sign = name_sign.encode(charset)
	size_sign = 0x20
	size_rest = 0x3C8E-size_sign
	date_size = 19
	with open(ori_file,'rb') as fori:
		# Read the original signature
		ori_sign = fori.read(size_sign)
		crc.update(ori_sign)
		print("Original signature: "+ori_sign.decode(charset))
		# Read the rest of the calibration
		ori_rest = fori.read(size_rest)
		crc.update(ori_rest)
		print("Original CRC: "+hex(crc.get()))
	with open(inp_file,'rb') as finp:
		# Ignore the signature in the modified calibration
		finp.seek(size_sign)
		inp_rest = finp.read(size_rest)
		crc.update_reverse(inp_rest)
		# Space padding
		size_space = size_sign - date_size - len(name_sign)
		for i in range(0, size_space):
			crc.update_reverse(b" ")
		crc_sign = crc.get()
		crc.reset()
		inp_free = finp.read()
	with open(out_file,'wb') as fout:
		# Write the new signature
		fout.write(name_sign)
		crc.update(name_sign)
		crc.initvalue = crc.get()
		date_sign = random_date_for_crc(crc, crc_sign)
		fout.write(date_sign)
		print("New signature: "+(name_sign+date_sign).decode(charset))
		print(" --> THIS IS A FAKE DATE TO MATCH THE ORIGINAL CRC")
		# Write the space padding
		for i in range(0, size_space):
			fout.write(b" ")
		fout.write(inp_rest)
		# Copy free space
		fout.write(inp_free)

def search_calrom_cpmlwi(cal_file, prog_file):
	crc = CRC16Reflect(0x8005, initvalue=0x0000) # CRC for calibration
	with open(cal_file, 'rb') as fcal:
		crc.update(fcal.read(0x3C8E))
		print("Calibration CRC: "+hex(crc.get()))
	opcode = ppc_cmplwi_opcode(0, crc.get())
	offset = 0
	with open("dump/ALS3M0244F/prog.bin", 'rb') as fprg:
		while(True):
			chunk = fprg.read(4)
			chunk_size = len(chunk)
			if(chunk_size == 0): break # EOF
			if(chunk == opcode):
				print("CRC cmplwi offset in "+prog_file+": "+hex(offset))
			offset += chunk_size

if __name__ == "__main__":	
	#crc = CRC16Normal(0x1021, initvalue=0x0123) # CRC for bootloader (not working yet), LUT is correct
	
	sign_calrom("dump/ALS3M0244F/calrom.bin", "calrom.bin", "calrom2.bin", "ALCANTOR ")
	search_calrom_cpmlwi("calrom2.bin", "dump/ALS3M0244F/prog.bin")

