import os
from lib.gui_tuner import MapTable, SimpleGauge
from lib.tuner_defs._10_black91 import TunerDefinition as Black91

# Some constants
BO_BE = 'big'

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

class TunerDefinition(Black91):
	IDENT = b"XTRACAL3"

	def __init__(self, lta):
		super().__init__(lta)
		self.name = "Lotus EngV0091 PATCHED"
		self.sym = HDRMap("patch/t4e/combined/patch.txt")
		self.afr_m = 10

	def read_extracal(self, symbol, offset, size):
		return self.lta.read_memory(self.sym.get_sym_addr("CAL_base_extra")+self.sym.get_sym_addr(symbol)+offset, size)

	def write_extracal(self, symbol, offset, data):
		self.lta.write_memory(self.sym.get_sym_addr("CAL_base_extra")+self.sym.get_sym_addr(symbol)+offset, data)

	def check(self):
		return super().check() and self.lta.read_memory(self.sym.get_sym_addr("CAL_base_extra"), 8) == TunerDefinition.IDENT

	def impcal(self, filename):
		super().impcal(filename)
		filename += ".xtracal"
		self.lta.upload(self.sym.get_sym_addr("CAL_base_extra"), filename)
		self.lta.verify(self.sym.get_sym_addr("CAL_base_extra"), filename)

	def expcal(self, filename):
		super().expcal(filename)
		filename += ".xtracal"
		self.lta.download(self.sym.get_sym_addr("CAL_base_extra"), self.sym.get_sym_addr("CAL_extra_size"), filename)
		self.lta.verify(self.sym.get_sym_addr("CAL_base_extra"), filename)

	def loop(self, force_ft0, force_os0):
		super().loop(force_ft0, force_os0)
		self.afr_m = self.read_u16(self.sym.get_sym_addr("wb_corr_adc"))*10/1023+10

	def gauges(self, parent):
		return super().gauges(parent)+[
		SimpleGauge(parent,
			"Ethanol",
			lambda: self.read_u8(self.sym.get_sym_addr("ethanol_content"))/2.55,
			"{:.1f} %",
			0, 85
		),
		SimpleGauge(parent,
			"Measured AFR",
			lambda: self.afr_m,
			"{:.2f} AFR",
			10, 20
		),
		SimpleGauge(parent,
			"Delta AFR",
			lambda: self.afr_m - self.afr_t,
			"{:.2f} AFR",
			-2, 2,
			font='Helvetica 16 bold'
		)]

	def maps(self, parent):
		return super().maps(parent)+[
		MapTable(parent,
			"ETHANOL Efficiency",
			lambda: [[int(v)/2 for v in self.read_extracal("OFF_CAL_ethanol_inj_efficiency", i*32, 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.write_extracal("OFF_CAL_ethanol_inj_efficiency", (y*32)+x, int(value*2).to_bytes(1, BO_BE)),
			0.5,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fa484, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3fa4a4, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"ETHANOL Ignition Low Cam",
			lambda: [[int(v)/4-10 for v in self.read_extracal("OFF_CAL_ethanol_ign_advance_low_cam_base", i*32, 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.write_extracal("OFF_CAL_ethanol_ign_advance_low_cam_base", (y*32)+x, int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fb30c, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3fb32c, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"ETHANOL Ignition High Cam",
			lambda: [[int(v)/4-10 for v in self.read_extracal("OFF_CAL_ethanol_ign_advance_high_cam_base", i*8, 8)] for i in range(8)],
			"{:.1f}",
			lambda x,y,value:self.write_extracal("OFF_CAL_ethanol_ign_advance_high_cam_base", (y*8)+x, int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fa2f4, 8)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3fa2fc, 8)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"ETHANOL Tip-In Adj. 1",
			lambda: [[int(v)*100/128 for v in self.read_extracal("OFF_CAL_ethanol_injtip_in_adj1", 0, 16)]],
			"{:.0f}",
			lambda x,y,value:self.write_extracal("OFF_CAL_ethanol_injtip_in_adj1", x, int(value*128/100).to_bytes(1, BO_BE)),
			1.0,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fa224, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"", lambda: [0], "{:d}", lambda: 0
		)]
