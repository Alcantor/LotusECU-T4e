#!/usr/bin/python3

import re, csv
import xml.etree.ElementTree as ET

# Read a CSV file into a dictionary, the first fow is ignored and
# the first column is used as key.
def read_csv(filename, convert=lambda v : v):
	units = {}
	with open(filename, "r") as f:
		c = csv.reader(f, delimiter=',', quotechar='"')
		# Ignore the title line
		next(c)
		for row in c:
			if(len(row) < 2): continue
			units[convert(row[0])] = row[1:]
	return units

# Parse "CAL_category_name", return (category, name)
def parse_CALentry(s):
	pattern = re.compile(r"[A-Z]+_([a-zA-Z0-9]+)_(.+)")
	m = pattern.match(s)
	if(not m): raise Exception("Error parsing CAL/LEA: "+s)
	return (m.group(1), m.group(2))

# Parse "var[size]", return (var, size)
def parse_var(s):
	pattern = re.compile(r"([^\[]+)(\[(\d+)\])?")
	m = pattern.match(s)
	if(not m): raise Exception("Error parsing var: "+s)
	var, size = m.group(1), m.group(3)
	if(not size): size = 1
	return (var, int(size))

def format_name(name):
	return name.replace("_", " ")

def xml_add_signature_calrom(rom):
	romid = ET.SubElement(rom, "romid")
	ET.SubElement(romid, "xmlid").text = "T4E2008"
	ET.SubElement(romid, "market").text = "World"
	ET.SubElement(romid, "make").text = "Lotus"
	ET.SubElement(romid, "model").text = "Elise/Exige"
	ET.SubElement(romid, "submodel").text = "2008-2011"
	ET.SubElement(romid, "transmission").text = "MT"
	ET.SubElement(romid, "filesize").text = "64kb"
	ET.SubElement(romid, "memmodel").text = "MPC563"
	ET.SubElement(romid, "flashmethod").text = "CRP"
	# TODO: Choose a better detection string!
	ET.SubElement(romid, "internalidaddress").text = "0x19"
	ET.SubElement(romid, "internalidstring").text = " "

def xml_add_signature_decram(rom):
	romid = ET.SubElement(rom, "romid")
	ET.SubElement(romid, "xmlid").text = "T4E2008 - Learned data"
	ET.SubElement(romid, "market").text = "World"
	ET.SubElement(romid, "make").text = "Lotus"
	ET.SubElement(romid, "model").text = "Elise/Exige"
	ET.SubElement(romid, "submodel").text = "2008-2011"
	ET.SubElement(romid, "transmission").text = "MT"
	ET.SubElement(romid, "filesize").text = "2kb"
	ET.SubElement(romid, "memmodel").text = "EEPROM"
	ET.SubElement(romid, "flashmethod").text = "CRP"
	ET.SubElement(romid, "internalidaddress").text = "0x0"
	ET.SubElement(romid, "internalidstring").text = "CroftT4E"
	#ET.SubElement(romid, "internalidstring").text = "CroftT4E090 14/07/2006 Lotus Eng"

def xml_add_scaling(table, unit):
	ET.SubElement(table, "scaling",
		category=unit[7],
		units=unit[1],
		expression=unit[2],
		to_byte=unit[3],
		format=unit[4],
		fineincrement=unit[5],
		coarseincrement=unit[6]
	)

def xml_add_2D_static(rom, lut, xv=None, xv_name="", xv_scaling=None):
	if(xv == None):
		xv = [format_name(lut[1])]

	if(int(lut[4]) != len(xv)):
		raise Exception("Invalid axis size: "+lut[1])

	table = ET.SubElement(rom, "table", type="2D",
		name=lut[0]+": "+format_name(lut[1]),
		category=lut[0],
		storagetype=lut[3][0],
		endian="big",
		sizex=str(len(xv)),
		userlevel="1",
		storageaddress="0x{:04X}".format(lut[2])
	)
	xml_add_scaling(table, lut[3])

	xaxis = ET.SubElement(table, "table", type="Static X Axis",
		name=xv_name,
		sizex=str(len(xv))
	)
	for v in xv:
		ET.SubElement(xaxis, "data").text = v
	if(xv_scaling): xml_add_scaling(xaxis, xv_scaling)

	ET.SubElement(table, "description").text = lut[5]

def xml_add_2D_fixed(rom, lut, xv_name, xv_scaling=None):
	xsize = int(lut[4])//2
	table = ET.SubElement(rom, "table", type="2D",
		name=lut[0]+": "+format_name(lut[1]),
		category=lut[0],
		storagetype=lut[3][0],
		endian="big",
		sizex=str(xsize),
		userlevel="1",
		storageaddress="0x{:04X}".format(lut[2]+xsize)
	)
	xml_add_scaling(table, lut[3])

	xaxis = ET.SubElement(table, "table", type="X Axis",
		name=xv_name,
		storagetype="uint8",
		endian="big",
		sizex=str(xsize),
		storageaddress="0x{:04X}".format(lut[2])
	)
	if(xv_scaling): xml_add_scaling(xaxis, xv_scaling)

	ET.SubElement(table, "description").text = lut[5]

def xml_add_2D(rom, lut, xv):
	if(lut[4] != xv[4]):
		raise Exception("Invalid axis size: "+lut[1])

	table = ET.SubElement(rom, "table", type="2D",
		name=lut[0]+": "+format_name(lut[1]),
		category=lut[0],
		storagetype=lut[3][0],
		endian="big",
		sizex=str(xv[4]),
		userlevel="1",
		storageaddress="0x{:04X}".format(lut[2])
	)
	xml_add_scaling(table, lut[3])

	xaxis = ET.SubElement(table, "table", type="X Axis",
		name=format_name(xv[1].split("_X_",1)[1]),
		storagetype=xv[3][0],
		endian="big",
		sizex=str(xv[4]),
		storageaddress="0x{:04X}".format(xv[2])
	)
	xml_add_scaling(xaxis, xv[3])

	ET.SubElement(table, "description").text = lut[5]

def xml_add_3D(rom, lut, xv, yv):
	if(lut[4] != xv[4]*yv[4]):
		raise Exception("Invalid axis size: "+lut[1])

	table = ET.SubElement(rom, "table", type="3D",
		name=lut[0]+": "+format_name(lut[1]),
		category=lut[0],
		storagetype=lut[3][0],
		endian="big",
		sizex=str(xv[4]),
		sizey=str(yv[4]),
		userlevel="1",
		storageaddress="0x{:04X}".format(lut[2])
	)
	xml_add_scaling(table, lut[3])

	xaxis = ET.SubElement(table, "table", type="X Axis",
		name=format_name(xv[1].split("_X_",1)[1]),
		storagetype=xv[3][0],
		endian="big",
		sizex=str(xv[4]),
		storageaddress="0x{:04X}".format(xv[2])
	)
	xml_add_scaling(xaxis, xv[3])

	yaxis = ET.SubElement(table, "table", type="Y Axis",
		name=format_name(yv[1].split("_Y_",1)[1]),
		storagetype=yv[3][0],
		endian="big",
		sizey=str(yv[4]),
		storageaddress="0x{:04X}".format(yv[2])
	)
	xml_add_scaling(yaxis, yv[3])

	ET.SubElement(table, "description").text = lut[5]

def xml_add_switch(rom, lut):
	table = ET.SubElement(rom, "table", type="Switch",
		name=lut[0]+": "+format_name(lut[1]),
		category=lut[0],
		sizey=str(lut[4]),
		userlevel="1",
		storageaddress="0x{:04X}".format(lut[2])
	)
	for v in lut[5]:
		ET.SubElement(table, "state", name=v[0], data=v[1])
	ET.SubElement(table, "description").text = lut[3]

units = read_csv("units.csv")
symbols = read_csv("symbols.csv")
xaxis = read_csv("xaxis.csv")
calbase = int(symbols["CAL_base"][0], 16)
leabase = int(symbols["LEA_base"][0], 16)

roms = ET.Element("roms")
calrom = ET.SubElement(roms, "rom")
decram = ET.SubElement(roms, "rom")

xml_add_signature_calrom(calrom)
xml_add_signature_decram(decram)

dim = 1
d_xaxis = None
d_yaxis = None
for s in symbols:
	if(s in ["CAL_base","LEA_base"]): continue
	if  (s.startswith("CAL_")):
		rom = calrom
		base = calbase
	elif(s.startswith("LEA_")):
		rom = decram
		base = leabase
	else:
		continue
	category, name = parse_CALentry(s)
	addr = int(symbols[s][0], 16)-base
	unit, size = parse_var(symbols[s][1])
	desc = symbols[s][2].replace("\\,",",")
	if(unit == "u8_obd2level"):
		xml_add_switch(rom, [category, name, addr, desc, 1, [
			("Level 0 DTC: off", "00"),
			("Level 0 DTC: off +self-heal", "40"),
			("Level 1 DTC: Permanent", "41"),
			("Level 1 DTC: Permanent, freeze frame (no overwrite)", "51"),
			("Level 2 DTC: Pending and Permanent", "42"),
			("Level 2 DTC: Pending and Permanent, freeze frame (overwrite level 1,3)", "52"),
			("Level 3 DTC: Pending and Permanent", "43"),
			("Level 3 DTC: Pending and Permanent, freeze frame (no overwrite)", "53"),
			("Level 4 DTC: Permanent", "44"),
			("Level 4 DTC: Permanent, freeze frame (overwrite level 1,3)", "54")
		]])
		continue
	if(s == "CAL_ecu_unlock_magic"):
		xml_add_switch(rom, [category, name, addr, desc, 4, [
			("Locked", "00 00 00 00"),
			("Unlocked", "57 54 46 3F")
		]])
		continue
	if(s == "CAL_misc_use_tmap"):
		xml_add_switch(rom, [category, name, addr, desc, 1, [
			("Use temperature of MAF sensor", "00"),
			("Use temperature of MAP sensor (after intercooler)", "01")
		]])
		continue
	if(s == "CAL_misc_use_tpms"):
		xml_add_switch(rom, [category, name, addr, desc, 1, [
			("No TPMS", "00"),
			("Use TPMS module", "01")
		]])
		continue
	if(s == "CAL_tc_mode"):
		xml_add_switch(rom, [category, name, addr, desc, 1, [
			("No traction control", "00"),
			("Normal traction control", "01"),
			("Variable traction control", "02")
		]])
		continue
	if(not unit in units):
		print("WARNING - Ignoring: "+s)
		continue
	data = [category, name, addr, units[unit], size, desc]

	if   "_X_" in name:
		dim += 1
		d_xaxis = data
	elif "_Y_" in name:
		dim += 1
		d_yaxis = data
	else:
		if(name == "shift_lights_before_rev_limit"):
			xml_add_2D_fixed(rom, data, "Gear Number", units['uint8_t'])
		elif(dim == 1):
			if(s in xaxis): xml_add_2D_static(rom, data, xaxis[s])
			elif(size > 1):
				if(s == "CAL_closedloop_enable_runtime"):
					xname = "stop coolant"
					shift = 4
					xunit = units['u8_temp_5/8-40c']
				elif(s == "CAL_injtip_catalyst_adj"):
					xname = "dfso_count"
					shift = 1
					xunit = units['uint8_t']
				elif(s == "CAL_sensor_fuel_scaling"):
					xname = "signal"
					shift = 1
					xunit = units['u8_voltage_5/1023v']
				else:
					print("WARNING - Using a fixed voltage scale for: "+s)
					xname = "signal"
					shift = 3
					xunit = units['u8_voltage_5/1023v']
				xml_add_2D_static(rom, data, [str(i<<(8-shift)) for i in range(0,size)], xname, xunit)
			else: xml_add_2D_static(rom, data)
		elif dim == 2: xml_add_2D(rom, data, d_xaxis)
		elif dim == 3: xml_add_3D(rom, data, d_xaxis, d_yaxis)
		dim = 1

tree = ET.ElementTree(roms)
ET.indent(tree, space="\t", level=0) # Python 3.9+ only
tree.write("T4e_defs.xml")
