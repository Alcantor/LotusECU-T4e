from lib.gui_tuner import MapTable, SimpleGauge

# Some constants
BO_BE = 'big'

class TunerDefinition:
	IDENT = b"BCroftT4E090 14/07/2006 Lotus EngV0091"

	def __init__(self, lta):
		self.lta = lta
		self.name = "Lotus EngV0091 Black Cluster"
		self.engine_speed_2 = 0
		self.load_1 = 0
		self.afr_t = 10

	def check(self):
		return self.lta.read_memory(0x078817, 38) == TunerDefinition.IDENT

	def read_u8(self, address):
		return int.from_bytes(self.lta.read_memory(address, 1), BO_BE)

	def read_u16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE)

	def read_i16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE, signed=True)

	def read_u32(self, address):
		return int.from_bytes(self.lta.read_memory(address, 4), BO_BE)

	def impcal(self, filename):
		self.lta.upload(0x3f98d0, filename)
		self.lta.verify(0x3f98d0, filename)

	def expcal(self, filename):
		self.lta.download(0x3f98d0, 0x3CB4, filename)
		self.lta.verify(0x3f98d0, filename)

	def loop(self, force_ft0, force_os0):
		self.engine_speed_2 = self.read_u16(0x3fd7f8)
		self.load_1 = self.read_u32(0x3fd8e4)
		self.afr_t = self.read_u16(0x3fd746)/100
		if(force_ft0):
			self.lta.write_memory(0x2f8148, b'\x80') # LTFT Zone 1
			self.lta.write_memory(0x2f8149, b'\x80') # LTFT Zone 2
			self.lta.write_memory(0x3fd972, b'\x00\x00') # STFT
			self.lta.write_memory(0x2f8152, b'\x00\x00') # Idle Trim
		if(force_os0):
			self.lta.write_memory(0x2f814a, b'\x00\x00\x00\x00\x00\x00\x00\x00')

	def gauges(self, parent):
		return [
		SimpleGauge(parent,
			"Engine Speed",
			lambda: self.engine_speed_2,
			"{:d} rpm",
			0, 8400
		),
		SimpleGauge(parent,
			"Engine Load",
			lambda: self.load_1,
			"{:d} mg/str.",
			60, 864
		),
		SimpleGauge(parent,
			"Coolant",
			lambda: self.read_u8(0x3fd666) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 110
		),
		SimpleGauge(parent,
			"Engine air",
			lambda: self.read_u8(0x3fd667) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 70
		),
		SimpleGauge(parent,
			"MAF Accumulated",
			lambda: self.read_u32(0x3fd5e0) / 1000,
			"{:.1f} g",
			0, 1000
		),
		SimpleGauge(parent,
			"TPS",
			lambda: self.read_u16(0x3fe41c) * 100 / 1023,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Tip In",
			lambda: self.read_u32(0x3fd81c),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Tip Out",
			lambda: self.read_u32(0x3fd820),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Injection Time",
			lambda: self.read_u16(0x304512),
			"{:d} us",
			0, 14285
		),
		SimpleGauge(parent,
			"Learn Dead Time",
			lambda: self.read_i16(0x2f8152),
			"{:d} us",
			-100, 100
		),
		SimpleGauge(parent,
			"STFT",
			lambda: self.read_i16(0x3fd972) / 20,
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"LTFT",
			lambda: self.read_i16(0x3fd978) / 10,
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"Target AFR",
			lambda: self.afr_t,
			"{:.2f} AFR",
			10, 20
		),
		SimpleGauge(parent,
			"Adv. Ign",
			lambda: self.read_i16(0x3fd6e4) / 4,
			"{:.2f} °",
			-10, 50
		),
		SimpleGauge(parent,
			"Octane Scaler #1",
			lambda: self.read_u16(0x2f814a + 0) / 655.36,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Octane Scaler #2",
			lambda: self.read_u16(0x2f814a + 2) / 655.36,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Octane Scaler #3",
			lambda: self.read_u16(0x2f814a + 4) / 655.36,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Octane Scaler #4",
			lambda: self.read_u16(0x2f814a + 6) / 655.36,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Pre O2 Current",
			lambda: self.read_u16(0x3fd682) / 1000,
			"{:.4f} A",
			0, 3
		),
		SimpleGauge(parent,
			"Post O2 Current",
			lambda: self.read_u16(0x3fd684) / 1000,
			"{:.4f} A",
			0, 3
		)
	]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[int(v)/2 for v in self.lta.read_memory(0x3fa4c4+(i*32), 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x3fa4c4+(y*32)+x,int(value*2).to_bytes(1, BO_BE)),
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
			"Ignition Low Cam",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x3fb34c+(i*32), 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x3fb34c+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE)),
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
			"Ignition High Cam",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x3fa304+(i*8), 8)] for i in range(8)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x3fa304+(y*8)+x,int((value+10)*4).to_bytes(1, BO_BE)),
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
			"VVT Advance Low Cam",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x3f9d24+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x3f9d24+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3f9d04, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3f9d14, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Advance High Cam",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x3fa924+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x3fa924+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fa904, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3fa914, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"AFR Target",
			lambda: [[int(v)/20+5 for v in self.lta.read_memory(0x3fd316+(i*16), 16)] for i in range(16)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x3fd316+(y*16)+x,int((value-5)*20).to_bytes(1, BO_BE)),
			0.1,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fd2f6, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x3fd306, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Inj Flow Rate",
			lambda: [[int.from_bytes(self.lta.read_memory(0x3f9ad0, 2), BO_BE)]],
			"{:.0f}",
			lambda x,y,value:self.lta.write_memory(0x3f9ad0,int(value).to_bytes(2, BO_BE)),
			1.0,

			"", lambda: [0], "{:d}", lambda: 0,
			"", lambda: [0], "{:d}", lambda: 0
		),
		MapTable(parent,
			"Tip-In Adj. 1",
			lambda: [[int(v)*100/128 for v in self.lta.read_memory(0x3fa1d4, 16)]],
			"{:.0f}",
			lambda x,y,value:self.lta.write_memory(0x3fa1d4+x,int(value*128/100).to_bytes(1, BO_BE)),
			1.0,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x3fa224, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"", lambda: [0], "{:d}", lambda: 0
		)]
