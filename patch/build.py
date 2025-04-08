#!/usr/bin/python3

import os, sys
sys.path.insert(0, '..')
from lib.ppc32 import PPC32

# Some constants
BO_BE = 'big'

class Patcher():
	def __init__(self, file, offset, size):
		self.data = memoryview(bytearray(size))
		self.offset=offset
		with open(file,'rb') as f: d = f.read()
		if(len(d) > size): raise Exception("File too big!")
		self.data[0:len(d)] = d
		for i in range(len(d), size): self.data[i] = 0xFF

	def check(self, addr, data):
		addr -= self.offset
		if(self.data[addr:addr+len(data)] != data):
			raise Exception("Unexpected data!")

	def replace(self, addr, data, size):
		if(size < len(data)): raise Exception("Too much data!")
		addr -= self.offset
		self.data[addr:addr+len(data)] = data
		for i in range(addr+len(data), addr+size): self.data[i] = 0xFF

	def check_and_replace(self, addr, old_data, new_data):
		self.check(addr, old_data)
		self.replace(addr, new_data, len(old_data))

	def search_and_replace(self, old_data, new_data, step=4):
		for i in range(0, len(self.data), step):
			if(self.data[i:i+len(old_data)] == old_data):
				self.replace(i, new_data, len(old_data))

	def check_blank(self, addr, size):
		addr -= self.offset
		for i in range(addr, addr+size):
			if(self.data[i] != 0xFF): raise Exception("Not blank!")

	def merge_file(self, addr, file, size=None, check_blank=True):
		with open(file,'rb') as f: data = f.read()
		if(size == None): size = len(data)
		if(check_blank): self.check_blank(addr, size)
		self.replace(addr, data, size)
		return size

	def get_freespace_pos(self):
		i = len(self.data)
		while(i > 0 and self.data[i-1] == 0xFF): i -= 1
		return i

	def get_freespace_addr(self):
		return self.get_freespace_pos()+self.offset

	def save(self, file, removeFreeSpace=True):
		with open(file,'wb') as f:
			if(removeFreeSpace):
				# 4 Bytes alignement
				addr = (self.get_freespace_pos() + 3) & ~3
				f.write(self.data[0:addr])
			else:
				f.write(self.data)

class Patcher_Prog(Patcher):
	def __init__(self, prog_file, offset, size, hint, instText, instBss):
		super().__init__(prog_file, offset, size)
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
		size = self.merge_file(rom_addr, file)
		self.segments.append((rom_addr, rom_addr, size))
		self.search_last_segments()

	def add_data(self, file, rom_addr, ram_addr):
		size = self.merge_file(rom_addr, file)
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
		super().__init__(boot_file, 0x00000, 0x10000)

class Patcher_T4eCalibration(Patcher):
	def __init__(self, cal_file, free_cal=None):
		super().__init__(cal_file, 0x10000, 0x10000)
		if(free_cal == None): self.free_cal = self.get_freespace_addr()
		else: self.free_cal = free_cal

	def get_free_cal(self):
		return self.free_cal

	def add_cal(self, file, rom_addr):
		self.merge_file(rom_addr, file)

class Patcher_T4eProg(Patcher_Prog):
	def __init__(self, prog_file):
		super().__init__(prog_file,
			0x20000, 0x60000,
			b"\x00\x02\x00\x00\x00\x02\x00\x00",
			lambda i: PPC32.ppc_addi(31, 3, i & 0xFFFF),
			lambda i: PPC32.ppc_addi(30, 3, i & 0xFFFF)
		)

class Patcher_T6Boot(Patcher):
	def __init__(self, boot_file):
		super().__init__(boot_file, 0x00000, 0x10000)

class Patcher_T6Calibration(Patcher):
	def __init__(self, cal_file, free_cal=None):
		super().__init__(cal_file, 0x20000, 0x20000)
		if(free_cal == None): self.free_cal = self.get_freespace_addr()
		else: self.free_cal = free_cal

	def get_free_cal(self):
		return self.free_cal

	def add_cal(self, file, rom_addr):
		self.merge_file(rom_addr, file)

class Patcher_T6Prog(Patcher_Prog):
	def __init__(self, prog_file):
		super().__init__(prog_file,
			0x40000, 0xC0000,
			b"\x00\x04\x00\x00\x00\x04\x00\x00",
			lambda i: PPC32.ppc_addi(31, 31, i & 0xFFFF),
			lambda i: PPC32.ppc_addi(31, 31, i & 0xFFFF)
		)

class HDRMap:
	def __init__(self, file):
		self.segs = {}
		self.syms = {}
		with open(file,'r') as f:
			chapter = 0
			for line in f.readlines():
				if(line.startswith("Sections:")):
					chapter = 1
					continue
				if(line.startswith("SYMBOL TABLE:")):
					chapter = 2
					continue
				if(len(line) <= 1):
					chapter = 0
					continue
				parts = line.split()
				if chapter == 1 and len(parts) == 7:
					self.segs[parts[1]] = (int(parts[4], 16), int(parts[2], 16))
				elif chapter == 2 and len(parts) >= 4:
					self.syms[parts[-1]] = int(parts[0], 16)
	def get_seg_addr(self, segment):
		return self.segs[segment][0]
	def get_seg_size(self, segment):
		return self.segs[segment][1]
	def get_sym_addr(self, symbol):
		return self.syms[symbol]

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
	p.merge_file(0x3000, "../flasher/t4e/canstrap-white.bin")
	p.save("t4e/stage15/white/bootldr.bin", False)

	print("Build black Stage 1.5...")
	p = Patcher_T4eBoot("../dump/t4e-black/A129E0002/bootldr.bin")
	p.search_and_replace(
		PPC32.ppc_ori(4, 4, 0x1FDC), # This value is also hardcoded in canstrap-black.bin
		PPC32.ppc_ori(4, 4, 0x9000)
	)
	p.merge_file(0x9000, "../flasher/t4e/canstrap-black.bin")
	p.save("t4e/stage15/black/bootldr.bin", False)

def build_combined():
	print("Combined T4e patch...")
	c = Patcher_T4eCalibration("../dump/t4e-black/A129E0002/calrom.bin")
	p = Patcher_T4eProg("../dump/t4e-black/A129E0002/prog.bin")
	accusump = input("Include accusump support (y/n) ? ")
	flexfuel = input("Include flexfuel support (y/n) ? ")
	obdoil   = input("Include obdoil support (y/n) ? ")
	wideband = input("Include wideband support (y/n) ? ")
	softvtc = input("Disable VTC knob sampling (y/n) ? ")
	os.system(
		"make -C t4e/combined clean all OBD_KLINE=n "
		"CAL=0x{:X} ROM=0x{:X} RAM=0x{:X} SYM={:s} "
		"ACCUSUMP={:s} FLEXFUEL={:s} OBDOIL={:s} WIDEBAND={:s}".format(
		c.get_free_cal(),
		p.get_free_rom(),
		p.get_free_ram(),
		"../black91.sym",
		accusump, flexfuel, obdoil, wideband
	))
	m = HDRMap("t4e/combined/patch.txt")

	# Hook: Init
	p.check_and_replace(
		m.get_sym_addr("hook_init_loc"),
		PPC32.ppc_li(0, 0x80),
		PPC32.ppc_ba(m.get_sym_addr("hook_init"))
	)

	# Hook: Main Loop
	p.check_and_replace(
		m.get_sym_addr("hook_loop_loc"),
		PPC32.ppc_b(
			m.get_sym_addr("hook_loop_continue") -
			m.get_sym_addr("hook_loop_loc")
		),
		PPC32.ppc_ba(m.get_sym_addr("hook_loop"))
	)

	# Hook: Timer 5ms
	p.check_and_replace(
		m.get_sym_addr("hook_timer_5ms_loc"),
		PPC32.ppc_li(5, 10),
		PPC32.ppc_ba(m.get_sym_addr("hook_timer_5ms"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		m.get_sym_addr("hook_OBD_mode_0x01_loc"),
		#PPC32.ppc_or(31, 3, 3),
		PPC32.ppc_rlwinm(0, 30, 0, 24, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x01"))
	)

	# Hook: OBD Mode 0x22
	p.check_and_replace(
		m.get_sym_addr("hook_OBD_mode_0x22_loc"),
		#PPC32.ppc_or(31, 3, 3),
		PPC32.ppc_rlwinm(29, 8, 0, 16, 31),
		PPC32.ppc_ba(m.get_sym_addr("hook_OBD_mode_0x22"))
	)

	if(accusump == 'y'):
		# Main Loop - Replace the call to the airbox_flap function
		p.check_and_replace(
			m.get_sym_addr("airbox_flap_call"),
			PPC32.ppc_bl(
				m.get_sym_addr("airbox_flap") -
				m.get_sym_addr("airbox_flap_call")
			),
			PPC32.ppc_bla(m.get_sym_addr("accusump"))
		)

	if(accusump == 'y' and obdoil != 'y'):
		# If we replace the digital oil sensor with an analogic one,
		# the oil pressure warning on the cluster will light up constantly!
		# We need to patch that too.
		p.check_and_replace(
			m.get_sym_addr("oilpressure_cmp"),
			PPC32.ppc_cmpli(3, 0x200), # Threshold at 2.5 V
			PPC32.ppc_cmpli(3, 0x0B8)  # Threshold at 1.0 bar.
		)

	if(flexfuel == 'y'):
		# Hook: High cam ignition
		p.check_and_replace(
			m.get_sym_addr("hook_ign_advance_high_cam_base_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_3D_uint8_interpolated") -
				m.get_sym_addr("hook_ign_advance_high_cam_base_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_high_cam_base"))
		)

		# Hook: Low cam ignition
		p.check_and_replace(
			m.get_sym_addr("hook_ign_advance_low_cam_base_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_3D_uint8_interpolated") -
				m.get_sym_addr("hook_ign_advance_low_cam_base_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_low_cam_base"))
		)

		# Hook: Ignition adj1
		p.check_and_replace(
			m.get_sym_addr("hook_ign_advance_adj1_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_2D_uint8_interpolated") -
				m.get_sym_addr("hook_ign_advance_adj1_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_ign_advance_adj1"))
		)

		# Hook: Injection cranking
		p.check_and_replace(
			m.get_sym_addr("hook_inj_time_adj_cranking_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_2D_uint8_interpolated") -
				m.get_sym_addr("hook_inj_time_adj_cranking_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_inj_time_adj_cranking"))
		)

		# Hook: Injection efficiency
		p.check_and_replace(
			m.get_sym_addr("hook_inj_efficiency_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_3D_uint8_interpolated") -
				m.get_sym_addr("hook_inj_efficiency_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_inj_efficiency"))
		)

		# Hook: Injection warmup
		p.check_and_replace(
			m.get_sym_addr("hook_inj_time_adj3_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_3D_uint8_interpolated") -
				m.get_sym_addr("hook_inj_time_adj3_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_inj_time_adj3"))
		)

		# Hook: Tip-In
		p.check_and_replace(
			m.get_sym_addr("hook_injtip_in_adj1_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_2D_uint8_interpolated") -
				m.get_sym_addr("hook_injtip_in_adj1_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_injtip_in_adj1"))
		)

		# Hook: Tip-Out
		p.check_and_replace(
			m.get_sym_addr("hook_injtip_out_adj1_loc"),
			PPC32.ppc_bl(
				m.get_sym_addr("lookup_2D_uint8_interpolated") -
				m.get_sym_addr("hook_injtip_out_adj1_loc")
			),
			PPC32.ppc_ba(m.get_sym_addr("hook_injtip_out_adj1"))
		)

	if(wideband == 'y'):
		# Patch to use wb_ht_th variable for pre o2 heater.
		# Power comes only when engine is running.
		addr = m.get_sym_addr("CAL_base")
		addr_ha1 = (addr >> 16) + ((addr >> 15) & 1)
		addr_l1 = addr & 0xFFFF
		addr = m.get_sym_addr("wb_ht_th")
		addr_ha2 = (addr >> 16) + ((addr >> 15) & 1)
		addr_l2 = addr & 0xFFFF
		p.check_and_replace(
			m.get_sym_addr("load_pre_O2_heater_threshold"),
			PPC32.ppc_lis(3, addr_ha1) + PPC32.ppc_addi(3, 3, addr_l1) +
			PPC32.ppc_lhz(0, 3, 0x2ca8),
			PPC32.ppc_lis(3, addr_ha2) + PPC32.ppc_addi(3, 3 ,addr_l2) +
			PPC32.ppc_lhz(0, 3, 0)
		)

		# Remove the write to sensor_adc_pre_O2
		p.check_and_replace(
			m.get_sym_addr("adc_sample_pre_O2"),
			PPC32.ppc_lis(3, 0x30),
			PPC32.ppc_b(0x18)
		)

	if(softvtc == 'y'):
		# Disable reading of VTC knob, so we can send it over can.
		p.check_and_replace(
			m.get_sym_addr("adc_sample_tc_knob"),
			PPC32.ppc_lis(3, 0x30),
			PPC32.ppc_b(0x18)
		)

	# Merge and save.
	p.add_text("t4e/combined/patch.text.bin", m.get_seg_addr(".text"))
	c.add_cal("t4e/combined/patch.data.bin", m.get_seg_addr(".data"))
	p.add_bss(m.get_seg_size(".bss"), m.get_seg_addr(".bss")) # TODO: Why 0x18, so much fill?
	p.write_segments()

	afr_ratio = (14.7/9) * (216/255)

	if(flexfuel == 'y'):
		# Copy Ignition adj
		addr_src = m.get_sym_addr("CAL_ign_advance_adj1")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_adj1") - c.offset
		for i in range(0, 16): c.data[addr_dst+i] = c.data[addr_src+i]

		# Copy ignition (high cam) table for ethanol.
		addr_src = m.get_sym_addr("CAL_ign_advance_high_cam_base")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_high_cam_base") - c.offset
		for i in range(0, 64): c.data[addr_dst+i] = c.data[addr_src+i]

		# Copy Tip-In table for ethanol, add more fuel.
		addr_src = m.get_sym_addr("CAL_injtip_in_adj1")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_injtip_in_adj1") - c.offset
		for i in range(0, 16):
			c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

		# Copy Tip-Out table for ethanol, add more fuel.
		addr_src = m.get_sym_addr("CAL_injtip_out_adj1")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_injtip_out_adj1") - c.offset
		for i in range(0, 16):
			c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

		# Copy fuel efficieny table for ethanol, add more fuel.
		addr_src = m.get_sym_addr("CAL_inj_efficiency")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_inj_efficiency") - c.offset
		for i in range(0, 1024):
			c.data[addr_dst+i] = int(c.data[addr_src+i]/afr_ratio)

		# Copy fuel warmup table for ethanol.
		addr_src = m.get_sym_addr("CAL_inj_time_adj3")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_inj_time_adj3") - c.offset
		for i in range(0, 256): c.data[addr_dst+i] = c.data[addr_src+i]

		# Copy fuel cranking table for ethanol, add more fuel.
		addr_src = m.get_sym_addr("CAL_inj_time_adj_cranking")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_inj_time_adj_cranking") - c.offset
		for i in range(0, 16):
			c.data[addr_dst+i] = min(int(c.data[addr_src+i]*afr_ratio), 255)

		# Copy ignition (low cam) table for ethanol.
		addr_src = m.get_sym_addr("CAL_ign_advance_low_cam_base")-m.get_sym_addr("CAL_base")
		addr_dst = m.get_sym_addr("CAL_ethanol_ign_advance_low_cam_base") - c.offset
		for i in range(0, 1024): c.data[addr_dst+i] = c.data[addr_src+i]

	p.save("t4e/combined/prog.bin")
	c.save("t4e/combined/calrom.bin")

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
	m = HDRMap("t6/flexfuel/flexfuel.txt")

	# Change SIU_PCR184 for primary function (Input RG4)
	p.check_and_replace(
		0x4285C,
		PPC32.ppc_li(0, 0x0100),
		PPC32.ppc_li(0, 0x0500)
	)

	# Hook: Init
	p.check_and_replace(
		m.get_sym_addr("hook_init_loc"),
		PPC32.ppc_li(0, 0x80),
		PPC32.ppc_ba(m.get_sym_addr("hook_init"))
	)

	# Hook: Main Loop
	p.check_and_replace(
		m.get_sym_addr("hook_loop_loc"),
		PPC32.ppc_b(
			m.get_sym_addr("hook_loop_continue") -
			m.get_sym_addr("hook_loop_loc")
		),
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
		m.get_sym_addr("hook_timer_5ms_loc"),
		PPC32.ppc_li(0, 10),
		PPC32.ppc_ba(m.get_sym_addr("hook_timer_5ms"))
	)

	# Hook: OBD Mode 0x01
	p.check_and_replace(
		m.get_sym_addr("hook_OBD_mode_0x01_loc"),
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
	build_combined()
	build_t6_flexfuel()
