#!/usr/bin/python3

import os, sys, re
sys.path.insert(0, '..')
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

	def resize(self, newsize):
		if(newsize <= len(self.data)):
			self.data = memoryview(self.data[0:newsize])
		else:
			newbuffer = bytearray(newsize)
			newbuffer[0:len(self.data)] = self.data;
			for i in range(len(self.data), newsize):
				newbuffer[i] = 0xFF
			self.data = memoryview(newbuffer)

class Patcher_Prog(Patcher):
	def __init__(self, prog_file, offset, hint, instText, instBss):
		super().__init__(prog_file, offset)
		self.hint = hint
		self.instText = instText
		self.instBss = instBss
		self.read_segments()
		self.search_last_segments()

	def read_segments(self):
		i = self.data.tobytes().find(self.hint)
		if(i == -1): raise Exception("First segment not found!")
		self.segments_table_offset = i
		self.segments = []

		# Search opcode which point to i.
		j = self.data.tobytes().find(self.instText(i))
		if(j == -1): raise Exception(".text/.data opcode not found!")
		self.opcode1_offset = j

		# Initialized data
		while(True):
			s = (
				int.from_bytes(self.data[i  :i+ 4], BO_BE),
				int.from_bytes(self.data[i+4:i+ 8], BO_BE),
				int.from_bytes(self.data[i+8:i+12], BO_BE)
			)
			i += 12
			if(s[2] == 0): break
			self.segments.append(s)

		# Ignore 0x0 (In some old versions).
		while(self.data[i:i+4] == b"\x00\x00\x00\x00"): i+=4

		# Search opcode which point to i.
		j = self.data.tobytes().find(self.instBss(i))
		if(j == -1): raise Exception(".bss opcode not found!")
		self.opcode2_offset = j

		# Uninitialized data
		while(True):
			s = (
				None,
				int.from_bytes(self.data[i  :i+4], BO_BE),
				int.from_bytes(self.data[i+4:i+8], BO_BE)
			)
			i += 8
			if(s[2] == 0): break
			self.segments.append(s)

		# How much free space is left?
		while(self.data[i:i+4] == b"\xFF\xFF\xFF\xFF"): i+=4
		self.blank_limit = i

	def write_segments(self):
		i = self.segments_table_offset

		# Replace opcode
		j = self.opcode1_offset
		self.data[j:j+4] = self.instText(i)

		# Initialized data
		for s in self.segments:
			if(s[0] == None): continue
			self.data[i  :i+ 4] = s[0].to_bytes(4, BO_BE)
			self.data[i+4:i+ 8] = s[1].to_bytes(4, BO_BE)
			self.data[i+8:i+12] = s[2].to_bytes(4, BO_BE)
			i += 12

		# End of initizialized data
		self.data[i:i+12] = bytes([0] * 12)
		i += 12

		# Replace opcode
		j = self.opcode2_offset
		self.data[j:j+4] = self.instBss(i)

		# Uninitialized data
		for s in self.segments:
			if(s[0] != None): continue
			self.data[i  :i+ 4] = s[1].to_bytes(4, BO_BE)
			self.data[i+4:i+ 8] = s[2].to_bytes(4, BO_BE)
			i += 8

		# End of uninitizialized data
		self.data[i:i+8] = bytes([0] * 8)
		i += 8

		# Verify that we do not overwrite something important.
		if(i > self.blank_limit):
			raise Exception("Not enough free space for segments!")

	def search_last_segments(self):
		# Search the upper segment in ROM and RAM
		upper_addr_src = 0
		upper_addr_dst = 0
		for s in self.segments:
			if(s[0] != None and upper_addr_src < s[0]):
				self.segment_last_rom = s
				upper_addr_src = s[0]
			if(upper_addr_dst < s[1]):
				self.segment_last_ram = s
				upper_addr_dst = s[1]

	def get_free_rom(self):
		return self.segment_last_rom[0]+self.segment_last_rom[2]

	def get_free_ram(self):
		return self.segment_last_ram[1]+self.segment_last_ram[2]

	def add_text(self, file, rom_addr):
		size = self.merge_file(rom_addr, file, check_blank=True)
		self.segments.append((rom_addr, rom_addr, size))
		self.search_last_segments()

	def add_data(self, file, rom_addr, ram_addr):
		size = self.merge_file(rom_addr, file, check_blank=True)
		self.segments.append((rom_addr, ram_addr, size))
		self.search_last_segments()

	def add_bss(self, size, ram_addr):
		self.segments.append((None, ram_addr, size))
		self.search_last_segments()

	def print_segments(self):
		print("Segments table 0x{:06X}:".format(self.segments_table_offset))
		for s in self.segments:
			if(s[0] == None): src = "--------"
			else: src = "0x{:06X}".format(s[0])
			print("  {:s} 0x{:06X} 0x{:06X}".format(src,s[1],s[2]))
		print("Free ROM space 0x{:06X}".format(self.get_free_rom()))
		print("Free RAM space 0x{:06X}".format(self.get_free_ram()))
		print("Opcode to .text/.data segments list 0x{:06X}".format(self.opcode1_offset))
		print("Opcode to .bss segments list 0x{:06X}".format(self.opcode2_offset))

class Patcher_T4eBoot(Patcher):
	def __init__(self, boot_file):
		super().__init__(boot_file, 0x00000)

class Patcher_T4eCalibration(Patcher):
	def __init__(self, cal_file, free_cal=None):
		super().__init__(cal_file, 0x10000)
		if(free_cal == None): self.free_cal = self.get_free_space()
		else: self.free_cal = free_cal

	def get_free_cal(self):
		return self.free_cal

	def add_cal(self, file, rom_addr):
		self.merge_file(rom_addr, file, check_blank=True)

class Patcher_T4eProg(Patcher_Prog):
	def __init__(self, prog_file):
		super().__init__(prog_file,
			0x20000,
			b"\x00\x02\x00\x00\x00\x02\x00\x00",
			lambda i: PPC32.ppc_addi(31, 3, i & 0xFFFF),
			lambda i: PPC32.ppc_addi(30, 3, i & 0xFFFF)
		)

class Patcher_T6Boot(Patcher):
	def __init__(self, boot_file):
		super().__init__(boot_file, 0x00000)

class Patcher_T6Calibration(Patcher):
	def __init__(self, cal_file, free_cal=None):
		super().__init__(cal_file, 0x20000)
		if(free_cal == None): self.free_cal = self.get_free_space()
		else: self.free_cal = free_cal

	def get_free_cal(self):
		return self.free_cal

	def add_cal(self, file, rom_addr):
		self.merge_file(rom_addr, file, check_blank=True)

class Patcher_T6Prog(Patcher_Prog):
	def __init__(self, prog_file):
		super().__init__(prog_file,
			0x40000,
			b"\x00\x04\x00\x00\x00\x04\x00\x00",
			lambda i: PPC32.ppc_addi(31, 31, i & 0xFFFF),
			lambda i: PPC32.ppc_addi(31, 31, i & 0xFFFF)
		)

class SYMMap:
	def __init__(self, file):
		self.syms = {}
		r = re.compile("^(.*) = (0x[0-9a-f]*);")
		with open(file,'r') as f:
			for line in f.readlines():
				m = r.match(line)
				if(m): self.syms[m.group(1)] = int(m.group(2), 16)

	def get_sym_addr(self, symbol):
		return self.syms[symbol]

class LDMap:
	def __init__(self, file):
		self.syms = {}
		self.segs = {}
		r_sym = re.compile("^ *(0x[0-9a-f]*) *([0-9a-zA-Z_]*)$")
		r_seg = re.compile("^(\.[a-z]*) *(0x[0-9a-f]*) *(0x[0-9a-f]*)$")
		with open(file,'r') as f:
			for line in f.readlines():
				m = r_sym.match(line)
				if(m): self.syms[m.group(2)] = int(m.group(1), 16)
				m = r_seg.match(line)
				if(m): self.segs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))

	def get_sym_addr(self, symbol):
		return self.syms[symbol]

	def get_seg_addr(self, segment):
		return self.segs[segment][0]

	def get_seg_size(self, segment):
		return self.segs[segment][1]

# Bootloader from ALS3M0240J seems ugly. Look at 0x400 for example.
# Bootloader A128E6009F, ALS3M0240F, ALS3M0244F and B120E0029F are identical
# except the ID and CRC.
def build_stage15():
	print("Build white Stage 1.5...")
	p = Patcher_T4eBoot("../dump/t4e-white/A128E6009F/bootldr.bin")
	p.search_and_replace(
		PPC32.ppc_ba(0x4000), # This value is also hardcoded in canstrap-white.bin
		PPC32.ppc_ba(0x3000)
	)
	p.merge_file(0x3000, "../flasher/t4e/canstrap-white.bin", check_blank=True)
	p.save("t4e/stage15/white/bootldr.bin")

	print("Build black Stage 1.5...")
	p = Patcher_T4eBoot("../dump/t4e-black/A129E0002/bootldr.bin")
	p.search_and_replace(
		PPC32.ppc_ori(4, 4, 0x1FDC), # This value is also hardcoded in canstrap-black.bin
		PPC32.ppc_ori(4, 4, 0x9000)
	)
	p.merge_file(0x9000, "../flasher/t4e/canstrap-black.bin", check_blank=True)
	p.save("t4e/stage15/black/bootldr.bin")

def build_accusump():
	print("Build accusump control...")
	c = Patcher_T4eCalibration("../dump/t4e-white/A128E6009F/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-white/A128E6009F/prog.bin")
	s = SYMMap("t4e/white78.sym")
	acis=s.get_sym_addr("airbox_flap")
	os.system("make -C t4e/accusump CAL=0x{:X} ROM=0x{:X} RAM=0x{:X}".format(
		c.get_free_cal(),
		acis, # p.get_free_rom(),
		p.get_free_ram(),
	))
	m = LDMap("t4e/accusump/map.txt")

	# If we replace the digital oil sensor with an analogic one,
	# the oil pressure warning on the cluster will light up constantly!
	# We need to patch that too.
	p.check_and_replace(
		s.get_sym_addr("oilpressure_cmp"),
		PPC32.ppc_cmpli(0, 0x200), # Threshold at 2.5 V
		PPC32.ppc_cmpli(0, 0x0B8)  # Threshold at 1.0 bar.
	)

	# Replace the ACIS function by the accusump control.
	p.merge_file(acis, "t4e/accusump/accusump.text.bin", size=0x100)

	# Default accusump calibration
	c.add_cal("t4e/accusump/accusump.data.bin", m.get_seg_addr(".data"))

	# Save
	p.save("t4e/accusump/prog.bin")
	c.save("t4e/accusump/calrom.bin")

def build_obdoil():
	print("OBD oil support...")
	c = Patcher_T4eCalibration("../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C t4e/obdoil CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	s = SYMMap("t4e/black91.sym")
	m = LDMap("t4e/obdoil/map.txt")

	# Hook: Main Loop
	p.check_and_replace(
		s.get_sym_addr("hook_loop_loc"),
		PPC32.ppc_b(-0x12B),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		s.get_sym_addr("hook_OBD_mode_0x01_loc"),
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Merge and save.
	p.add_text("t4e/obdoil/obdoil.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t4e/obdoil/obdoil.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss")) # TODO: Why 0x10, so much fill?
	p.write_segments()
	p.save("t4e/obdoil/prog.bin")
	c.save("t4e/obdoil/calrom.bin")

	# Test
	#p.print_segments()

def build_accusump2():
	print("Accusump2 support...")
	#c = Patcher_T4eCalibration("../dump/t4e-black/A128E0031/calrom.bin")
	c = Patcher_T4eCalibration("../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C t4e/accusump2 CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	s = SYMMap("t4e/black91.sym")
	m = LDMap("t4e/accusump2/map.txt")

	# If we replace the digital oil sensor with an analogic one,
	# the oil pressure warning on the cluster will light up constantly!
	# We need to patch that too.
	p.check_and_replace(
		s.get_sym_addr("oilpressure_cmp"),
		PPC32.ppc_cmpli(3, 0x200), # Threshold at 2.5 V
		PPC32.ppc_cmpli(3, 0x0B8)  # Threshold at 1.0 bar.
	)

	# Hook: Init
	p.check_and_replace(
		s.get_sym_addr("hook_init2_loc"),
		PPC32.ppc_blr(),
		PPC32.ppc_ba(m.get_sym_addr("hook_init2"))
	)

	# Main Loop - Replace the call to the airbox_flap function
	p.check_and_replace(
		s.get_sym_addr("airbox_flap"),
		PPC32.ppc_bl(0x01a9dc),
		PPC32.ppc_bla(m.get_sym_addr("accusump"))
	)

	# Hook: Timer 5ms
	p.check_and_replace(
		s.get_sym_addr("hook_timer_5ms_loc"),
		PPC32.ppc_li(5, 10),
		PPC32.ppc_ba(m.get_sym_addr("hook_timer_5ms"))
	)

	# Hook: OBD Mode 0x22
	p.check_and_replace(
		s.get_sym_addr("hook_OBD_mode_0x22_loc"),
		PPC32.ppc_rlwinm(29, 8, 0, 16, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x22"))
	)

	# Merge and save.
	p.add_text("t4e/accusump2/accusump2.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t4e/accusump2/accusump2.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss")) # TODO: Why 8, so much fill?
	p.write_segments()
	p.save("t4e/accusump2/prog.bin")
	c.save("t4e/accusump2/calrom.bin")

	# Test
	#p.print_segments()

def build_flexfuel():
	print("Flexfuel support...")
	c = Patcher_T4eCalibration("../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C t4e/flexfuel CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	s = SYMMap("t4e/black91.sym")
	m = LDMap("t4e/flexfuel/map.txt")

	# Hook: Init
	p.check_and_replace(
		s.get_sym_addr("hook_init_loc"),
		PPC32.ppc_li(0, 0x80),
		PPC32.ppc_ba(m.get_sym_addr("hook_init"))
	)

	# Hook: Main Loop
	p.check_and_replace(
		s.get_sym_addr("hook_loop_loc"),
		PPC32.ppc_b(-0x12B),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: Timer 5ms
	p.check_and_replace(
		s.get_sym_addr("hook_timer_5ms_loc"),
		PPC32.ppc_li(5, 10),
		PPC32.ppc_ba(m.get_sym_addr("hook_timer_5ms"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		s.get_sym_addr("hook_OBD_mode_0x01_loc"),
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Hook: High cam ignition
	p.check_and_replace(
		s.get_sym_addr("hook_ign_advance_high_cam_base_loc"),
		PPC32.ppc_bl(-0x1061C),
		PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_high_cam_base"))
	)

	# Hook: Low cam ignition
	p.check_and_replace(
		s.get_sym_addr("hook_ign_advance_low_cam_base_loc"),
		PPC32.ppc_bl(-0x106E0),
		PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_low_cam_base"))
	)

	# Hook: Ignition adj1
	p.check_and_replace(
		s.get_sym_addr("hook_ign_advance_adj1_loc"),
		PPC32.ppc_bl(-0x10C50),
		PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_adj1"))
	)

	# Hook: Injection cranking
	p.check_and_replace(
		s.get_sym_addr("hook_inj_time_adj_cranking_loc"),
		PPC32.ppc_bl(-0x12F50),
		PPC32.ppc_ba(m.get_sym_addr("hook_inj_time_adj_cranking"))
	)

	# Hook: Injection efficiency
	p.check_and_replace(
		s.get_sym_addr("hook_inj_efficiency_loc"),
		PPC32.ppc_bl(-0x12E5C),
		PPC32.ppc_ba(m.get_sym_addr("hook_inj_efficiency"))
	)

	# Hook: Injection warmup
	p.check_and_replace(
		s.get_sym_addr("hook_inj_time_adj3_loc"),
		PPC32.ppc_bl(-0x1301C),
		PPC32.ppc_ba(m.get_sym_addr("hook_inj_time_adj3"))
	)

	# Hook: Tip-In
	p.check_and_replace(
		s.get_sym_addr("hook_injtip_in_adj1_loc"),
		PPC32.ppc_bl(-0x16274),
		PPC32.ppc_ba(m.get_sym_addr("hook_injtip_in_adj1"))
	)

	# Hook: Tip-Out
	p.check_and_replace(
		s.get_sym_addr("hook_injtip_out_adj1_loc"),
		PPC32.ppc_bl(-0x1631C),
		PPC32.ppc_ba(m.get_sym_addr("hook_injtip_out_adj1"))
	)

	# Merge and save.
	p.add_text("t4e/flexfuel/flexfuel.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t4e/flexfuel/flexfuel.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss")) # TODO: Why 0x18, so much fill?
	p.write_segments()

	afr_ratio = (14.7/9) * (216/255)

	# Copy Ignition adj
	addr_src = s.get_sym_addr("CAL_ign_advance_adj1")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_adj1") - c.offset
	for i in range(0, 16): c.data[addr_dst+i] = c.data[addr_src+i]

	# Copy ignition (high cam) table for ethanol.
	addr_src = s.get_sym_addr("CAL_ign_advance_high_cam_base")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_high_cam_base") - c.offset
	for i in range(0, 64): c.data[addr_dst+i] = c.data[addr_src+i]

	# Copy Tip-In table for ethanol, add more fuel.
	addr_src = s.get_sym_addr("CAL_injtip_in_adj1")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_injtip_in_adj1") - c.offset
	for i in range(0, 16):
		c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

	# Copy Tip-Out table for ethanol, add more fuel.
	addr_src = s.get_sym_addr("CAL_injtip_out_adj1")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_injtip_out_adj1") - c.offset
	for i in range(0, 16):
		c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

	# Copy fuel efficieny table for ethanol, add more fuel.
	addr_src = s.get_sym_addr("CAL_inj_efficiency")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_inj_efficiency") - c.offset
	for i in range(0, 1024):
		c.data[addr_dst+i] = int(c.data[addr_src+i]/afr_ratio)

	# Copy fuel warmup table for ethanol.
	addr_src = s.get_sym_addr("CAL_inj_time_adj3")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_inj_time_adj3") - c.offset
	for i in range(0, 256): c.data[addr_dst+i] = c.data[addr_src+i]

	# Copy fuel cranking table for ethanol, add more fuel.
	addr_src = s.get_sym_addr("CAL_inj_time_adj_cranking")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_inj_time_adj_cranking") - c.offset
	for i in range(0, 16):
		c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

	# Copy ignition (low cam) table for ethanol.
	addr_src = s.get_sym_addr("CAL_ign_advance_low_cam_base")-s.get_sym_addr("CAL_base")
	addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_low_cam_base") - c.offset
	for i in range(0, 1024): c.data[addr_dst+i] = c.data[addr_src+i]

	p.save("t4e/flexfuel/prog.bin")
	c.save("t4e/flexfuel/calrom.bin")

	# Test
	#p.print_segments()

def build_wideband():
	print("Wideband support...")
	c = Patcher_T4eCalibration("../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-black/A129E0002/prog.bin")
	os.system("make -C t4e/wideband CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym"
	))
	s = SYMMap("t4e/black91.sym")
	m = LDMap("t4e/wideband/map.txt")

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		s.get_sym_addr("hook_OBD_mode_0x01_loc"),
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Patch to always have power to the pre-lambda (for a wideband controller).
	# Power comes only when engine is running.
	p.check_and_replace(
		0x0339b0,
		PPC32.ppc_li(4, 0),
		PPC32.ppc_li(4, 1)
	)

	# Simulate a Narrow-Band lambda
	p.check_and_replace(
		s.get_sym_addr("hook_narrow_sim_loc"),
		PPC32.ppc_rlwinm(0, 0, 0, 16, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_narrow_sim"))
	)

	# Merge and save.
	p.add_text("t4e/wideband/wideband.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t4e/wideband/wideband.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss"))
	p.write_segments()
	p.save("t4e/wideband/prog.bin")
	c.save("t4e/wideband/calrom.bin")

	# Test
	#p.print_segments()

def build_t6_flexfuel():
	print("Flexfuel T6 support...")
	c = Patcher_T6Calibration("../dump/t6/P138E0009/calrom.bin")
	p = Patcher_T6Prog("../dump/t6/P138E0009/prog.bin")
	os.system("make -C t6/flexfuel CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../T6-V000S.sym"
	))
	s = SYMMap("t6/T6-V000S.sym")
	m = LDMap("t6/flexfuel/map.txt")

	# Change SIU_PCR184 for primary function (Input RG4)
	p.check_and_replace(
		0x4285C,
		PPC32.ppc_li(0, 0x0100),
		PPC32.ppc_li(0, 0x0500)
	)

	# Hook: Init
	p.check_and_replace(
		s.get_sym_addr("hook_init_loc"),
		PPC32.ppc_li(0, 0x80),
		PPC32.ppc_ba(m.get_sym_addr("hook_init"))
	)

	# Hook: Main Loop
	p.check_and_replace(
		s.get_sym_addr("hook_loop_loc"),
		PPC32.ppc_b(-0x29C),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: Main Loop Correction
	p.check_and_replace(
		0x43050,
		PPC32.ppc_ble(-0x280),
		PPC32.ppc_ble( 0x1C)
	)

	# Hook: Timer 5ms
	p.check_and_replace(
		s.get_sym_addr("hook_timer_5ms_loc"),
		PPC32.ppc_li(0, 10),
		PPC32.ppc_ba(m.get_sym_addr("hook_timer_5ms"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		s.get_sym_addr("hook_OBD_mode_0x01_loc"),
		PPC32.ppc_rlwinm(0, 3, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Move the pointer for the freeram counter
	addr = m.get_seg_addr(".bss") + m.get_seg_size(".bss")
	addr_ha = (addr >> 16) + ((addr >> 15) & 1)
	addr_l = addr & 0xFFFF
	p.check_and_replace(
		0x4307C,
		PPC32.ppc_lis(3, 0x4001) + PPC32.ppc_addi(0, 3, -0x1000),
		PPC32.ppc_lis(3, addr_ha) + PPC32.ppc_addi(0, 3, addr_l)
	)

	# Resize if needed
	p.resize(0xC0000)
	c.resize(0x10000)

	# Merge and save.
	p.add_text("t6/flexfuel/flexfuel.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t6/flexfuel/flexfuel.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss"))
	#p.write_segments()
	p.save("t6/flexfuel/prog.bin")
	c.save("t6/flexfuel/calrom.bin")

	# Test
	#p.print_segments()

if __name__ == "__main__":
	build_stage15()
	build_accusump()
	build_obdoil()
	build_accusump2()
	build_flexfuel()
	build_wideband()
	build_t6_flexfuel()
