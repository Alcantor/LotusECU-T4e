#!/usr/bin/python3

import os, sys, re
sys.path.insert(0, '../..')
from lib.ppc32 import PPC32

# Some constants
BO_BE = 'big'

class Patcher():
	def __init__(self, file, offset):
		with open(file,'rb') as f:
			self.data = memoryview(bytearray(f.read()))
		self.offset=offset

	def check(self, addr, data):
		addr -= self.offset
		if(self.data[addr:addr+len(data)] != data):
			raise Exception("Unexpected data!")

	def replace(self, addr, data, size, blank=0xFF):
		if(size < len(data)): raise Exception("Too much data!")
		addr -= self.offset
		self.data[addr:addr+len(data)] = data
		for i in range(addr+len(data), addr+size): self.data[i] = blank

	def check_and_replace(self, addr, old_data, new_data):
		self.check(addr, old_data)
		self.replace(addr, new_data, len(old_data))

	def search_and_replace(self, old_data, new_data, step=4):
		for i in range(0, len(self.data), step):
			if(self.data[i:i+len(old_data)] == old_data):
				self.replace(i, new_data, len(old_data))

	def check_blank(self, addr, size, blank=0xFF):
		addr -= self.offset
		for i in range(addr, addr+size):
			if(self.data[i] != blank): raise Exception("Not blank!")

	def merge_file(self, addr, file, size=None, check_blank=False):
		with open(file,'rb') as f: data = f.read()
		if(size == None): size = len(data)
		if(check_blank): self.check_blank(addr, size)
		self.replace(addr, data, size)
		return size

	def get_free_space(self, blank=0xFF):
		i = len(self.data)
		while(i > 0 and self.data[i-1] == blank): i -= 1
		return i+self.offset

	def save(self, file):
		with open(file,'wb') as f: f.write(self.data)

class Patcher_T4eBoot(Patcher):
	def __init__(self, prog_file):
		super().__init__(prog_file, 0x00000)

class Patcher_T4eCalibration(Patcher):
	def __init__(self, prog_file, free_cal=None):
		super().__init__(prog_file, 0x10000)
		if(free_cal == None): self.free_cal = self.get_free_space()
		else: self.free_cal = free_cal

	def get_free_cal(self):
		return self.free_cal

	def add_cal(self, file):
		self.merge_file(self.get_free_cal(), file, check_blank=True)

class Segment:
	def __init__(self, src, dest, size):
		self.src = src
		self.dest = dest
		self.size = size
	def get_src(self): return int.from_bytes(self.src, BO_BE)
	def get_dest(self): return int.from_bytes(self.dest, BO_BE)
	def get_size(self): return int.from_bytes(self.size, BO_BE)
	def get_src_end(self): return self.get_src()+self.get_size()
	def get_dest_end(self): return self.get_dest()+self.get_size()
	def inc_size(self, size):
		self.size[:] = (self.get_size()+size).to_bytes(4, BO_BE)
	def __str__(self):
		if(self.src == None): src = "--------"
		else: src = "0x{:06X}".format(self.get_src())
		return "{:s} 0x{:06X} 0x{:06X}".format(
			src,
			self.get_dest(),
			self.get_size()
		)

class Patcher_T4eProg(Patcher):
	def __init__(self, prog_file):
		super().__init__(prog_file, 0x20000)
		self.detect_segments()

	def detect_segments(self):
		i = self.data.tobytes().find(b"\x00\x02\x00\x00\x00\x02\x00\x00")
		if(i == -1): raise Exception("First segment not found!")
		self.segments = []
		# Initialized data
		while(True):
			segment = Segment(
				self.data[i:i+4],
				self.data[i+4:i+8],
				self.data[i+8:i+12]
			)
			i += 12
			if(segment.get_size() == 0): break
			self.segments.append(segment)
		# Ignore 0x0
		while(self.data[i:i+4] == b"\x00\x00\x00\x00"): i+=4
		# Uninitialized data
		while(True):
			segment = Segment(
				None,
				self.data[i:i+4],
				self.data[i+4:i+8]
			)
			i += 8
			if(segment.get_size() == 0): break
			self.segments.append(segment)
		# Search the upper segment in ROM and RAM
		upper_addr = 0
		for s in self.segments:
			if(s.src != None and upper_addr < s.get_src()):
				self.segment_last_rom = s
				upper_addr = s.get_src()
		upper_addr = 0
		for s in self.segments:
			if(upper_addr < s.get_dest()):
				self.segment_last_ram = s
				upper_addr = s.get_dest()

	def get_free_rom(self):
		return self.segment_last_rom.get_src_end()

	def get_free_ram(self):
		return self.segment_last_ram.get_dest_end()

	def add_rom(self, file):
		size = self.merge_file(self.get_free_rom(), file, check_blank=True)
		self.segment_last_rom.inc_size(size)

	def add_ram(self, size):
		self.segment_last_ram.inc_size(size)

	def print_segments(self):
		for s in self.segments: print(s)
		print("Free ROM space 0x{:06X}".format(self.get_free_rom()))
		print("Free RAM space 0x{:06X}".format(self.get_free_ram()))

class LDMap:
	def __init__(self, file):
		with open(file,'r') as f:
			self.lines = f.readlines()

	def get_sym_addr(self, symbol):
		r = re.compile("^ *(0x[0-9a-f]*) *"+symbol+"$")
		for line in self.lines:
			m = r.match(line)
			if(m): return int(m.group(1), 16)
		raise Exception("Symbol not found!")

	def get_seg_size(self, segment):
		r = re.compile("^"+segment+" *0x[0-9a-f]* *(0x[0-9a-f]*)")
		for line in self.lines:
			m = r.match(line)
			if(m): return int(m.group(1), 16)
		raise Exception("Segment not found!")

# Bootloader from ALS3M0240J seems ugly. Look at 0x400 for example.
# Bootloader A128E6009F, ALS3M0240F, ALS3M0244F and B120E0029F are identical
# except the ID and CRC.
def build_stage15():
	print("Build white Stage 1.5...")
	p = Patcher_T4eBoot("../../dump/t4e-white/A128E6009F/bootldr.bin")
	p.search_and_replace(
		PPC32.ppc_ba(0x4000), # This value is also hardcoded in canstrap-white.bin
		PPC32.ppc_ba(0x3000)
	)
	p.merge_file(0x3000, "../../flasher/t4e/canstrap-white.bin", check_blank=True)
	p.save("stage15/white/bootldr.bin")

	print("Build black Stage 1.5...")
	p = Patcher_T4eBoot("../../dump/t4e-black/A129E0002/bootldr.bin")
	p.search_and_replace(
		PPC32.ppc_ori(4, 4, 0x1FDC), # This value is also hardcoded in canstrap-black.bin
		PPC32.ppc_ori(4, 4, 0x9000)
	)
	p.merge_file(0x9000, "../../flasher/t4e/canstrap-black.bin", check_blank=True)
	p.save("stage15/black/bootldr.bin")

def build_accusump():
	print("Build accusump control...")
	c = Patcher_T4eCalibration("../../dump/t4e-white/A128E6009F/calrom.bin")
	p = Patcher_T4eProg("../../dump/t4e-white/A128E6009F/prog.bin")
	acis=0x3BC58
	os.system("make -C accusump CAL=0x{:X} ROM=0x{:X} RAM=0x{:X}".format(
		c.get_free_cal(),
		acis, # p.get_free_rom(),
		p.get_free_ram(),
	))

	# If we replace the digital oil sensor with an analogic one,
	# the oil pressure warning on the cluster will light up constantly!
	# We need to patch that too.
	p.check_and_replace(
		0x3BAB4,
		PPC32.ppc_cmpli(0, 0x200), # Threshold at 2.5 V
		PPC32.ppc_cmpli(0, 0x0B8)  # Threshold at 1.0 bar.
	)

	# Replace the ACIS function by the accusump control.
	p.merge_file(acis, "accusump/accusump.text.bin", size=0x100)

	# Default accusump calibration
	c.add_cal("accusump/accusump.data.bin")

	# Save
	p.save("accusump/prog.bin")
	c.save("accusump/calrom.bin")

def build_obdoil():
	print("OBD oil support...")
	c = Patcher_T4eCalibration("../../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C obdoil CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	m = LDMap("obdoil/map.txt")

	# If we replace the digital oil sensor with an analogic one,
	# the oil pressure warning on the cluster will light up constantly!
	# We need to patch that too.
	p.check_and_replace(
		0x03cb04,
		PPC32.ppc_cmpli(3, 0x200), # Threshold at 2.5 V
		PPC32.ppc_cmpli(3, 0x0B8)  # Threshold at 1.0 bar.
	)

	# Hook: Main Loop
	p.check_and_replace(
		0x023578,
		PPC32.ppc_b(-0x12B),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		0x05d778,
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Merge and save.
	p.add_rom("obdoil/obdoil.text.bin")
	c.add_cal("obdoil/obdoil.data.bin")
	p.add_ram(m.get_seg_size(".bss")) # TODO: Why 0x10, so much fill?
	p.save("obdoil/prog.bin")
	c.save("obdoil/calrom.bin")

	# Test
	#p.print_segments()

def build_accusump2():
	print("Accusump2 support...")
	#c = Patcher_T4eCalibration("../../dump/t4e-black/A128E0031/calrom.bin")
	c = Patcher_T4eCalibration("../../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C accusump2 CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	m = LDMap("accusump2/map.txt")

	# If we replace the digital oil sensor with an analogic one,
	# the oil pressure warning on the cluster will light up constantly!
	# We need to patch that too.
	p.check_and_replace(
		0x03cb04,
		PPC32.ppc_cmpli(3, 0x200), # Threshold at 2.5 V
		PPC32.ppc_cmpli(3, 0x0B8)  # Threshold at 1.0 bar.
	)

	# Main Loop - Replace the call to the airbox_flap function
	p.check_and_replace(
		0x23564,
		PPC32.ppc_bl(0x01a9dc),
		PPC32.ppc_bla(m.get_sym_addr("accusump"))
	)

	# Hook: OBD Mode 0x22
	p.check_and_replace(
		0x06486c,
		PPC32.ppc_rlwinm(29, 8, 0, 16, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x22"))
	)

	# Merge and save.
	p.add_rom("accusump2/accusump2.text.bin")
	c.add_cal("accusump2/accusump2.data.bin")
	p.add_ram(m.get_seg_size(".bss")) # TODO: Why 8, so much fill?
	p.save("accusump2/prog.bin")
	c.save("accusump2/calrom.bin")

	# Test
	#p.print_segments()

def build_flexfuel():
	print("Flexfuel support...")
	c = Patcher_T4eCalibration("../../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C flexfuel CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	m = LDMap("flexfuel/map.txt")

	# Hook: Init
	p.check_and_replace(
		0x03009c,
		PPC32.ppc_blr(),
		PPC32.ppc_ba(m.get_sym_addr("hook_init"))
	)

	# Hook: Main Loop
	p.check_and_replace(
		0x023578,
		PPC32.ppc_b(-0x12B),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		0x05d778,
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Blend: AFR
	#p.check_and_replace(
	#	0x036594,
	#	b"\x4b\xfe\xd3\x9d", # TODO: Replace with PPC32.ppc_bl(-?)
	#	PPC32.ppc_bla(0x07ead8) # TODO: Parse map.txt to get this value!
	#)

	# Merge and save.
	p.add_rom("flexfuel/flexfuel.text.bin")
	c.add_cal("flexfuel/flexfuel.data.bin")
	p.add_ram(m.get_seg_size(".bss")) # TODO: Why 0x18, so much fill?
	p.save("flexfuel/prog.bin")
	c.save("flexfuel/calrom.bin")

	# Test
	#p.print_segments()

if __name__ == "__main__":
	build_stage15()
	build_accusump()
	build_obdoil()
	build_accusump2()
	build_flexfuel()

