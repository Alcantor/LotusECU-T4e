#!/usr/bin/python3

import sys, datetime
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
	size_date = 19
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
		# Read the rest of the modified calibration
		inp_rest = finp.read(size_rest)
		crc.update_reverse(inp_rest)
		# Read the free space
		inp_free = finp.read()
	# Space padding
	if(len(name_sign) > (size_sign - size_date)):
		raise Exception("Signature is too long")
	size_space = size_sign - size_date - len(name_sign)
	for i in range(0, size_space): crc.update_reverse(b" ")
	crc_sign = crc.get()
	crc.reset()
	# Magic
	crc.update(name_sign)
	crc.set_initvalue(crc.get())
	date_sign = random_date_for_crc(crc, crc_sign)
	print("New signature: "+(name_sign+date_sign).decode(charset))
	print(" --> THIS IS A FAKE DATE TO MATCH THE ORIGINAL CRC")
	with open(out_file,'wb') as fout:
		# Write the new signature
		fout.write(name_sign)
		fout.write(date_sign)
		# Write the space padding
		for i in range(0, size_space): fout.write(b" ")
		# Write the rest of the calibration
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
	with open(prog_file, 'rb') as fprg:
		while(True):
			chunk = fprg.read(4)
			chunk_size = len(chunk)
			if(chunk_size == 0): break # EOF
			if(chunk == opcode):
				print("CRC cmplwi offset in "+prog_file+": "+hex(offset))
				return
			offset += chunk_size
		print("CRC not found in "+prog_file)

if __name__ == "__main__":
	print("CRC tool for Lotus T4e ECU\n")
	if  (len(sys.argv) >= 6 and sys.argv[1] == "sign_calrom"):
		sign_calrom(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]+" ")
	elif(len(sys.argv) >= 4 and sys.argv[1] == "search_crc_prog"):
		search_calrom_cpmlwi(sys.argv[2], sys.argv[3])
	else:
		print("usage:")
		print("\t"+sys.argv[0]+" sign_calrom ORIGINAL_CALROM MODIFIED_CALROM OUTFILE SIGNATURE")
		print("\t"+sys.argv[0]+" search_crc_prog ORIGINAL_CALROM ORIGINAL_PROG")

	# CRC for bootloader (not working yet), LUT is correct
	# crc = CRC16Normal(0x1021, initvalue=0x0123)

