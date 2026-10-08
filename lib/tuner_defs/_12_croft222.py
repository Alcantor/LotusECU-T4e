from lib.gui_tuner import MapTable, SimpleGauge

# Some constants
BO_BE = 'big'

class TunerDefinition:
	IDENT = b"Croft222  8th Feb  06 Lotus Eng"

	def __init__(self, lta):
		self.lta = lta
		self.name = "Lotus T4 Croft222 (D120E06H)"
		self.engine_speed_2 = 0
		self.load_1 = 0
		self.afr_t = 10

	def check(self):
		return self.lta.read_memory(0x2f082, 31) == TunerDefinition.IDENT

	def read_u8(self, address):
		return int.from_bytes(self.lta.read_memory(address, 1), BO_BE)

	def read_u16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE)

	def read_i16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE, signed=True)

	def read_u32(self, address):
		return int.from_bytes(self.lta.read_memory(address, 4), BO_BE)

	def impcal(self, filename):
		self.lta.upload(0x84000, filename)
		self.lta.verify(0x84000, filename)

	def expcal(self, filename):
		self.lta.download(0x84000, 0x3C9C, filename)
		self.lta.verify(0x84000, filename)

	def loop(self, force_ft0, force_os0):
		self.engine_speed_2 = self.read_u16(0x801c8)
		self.load_1 = self.read_u32(0x80cf8)
		self.afr_t = self.read_u16(0x808d8) / 100
		if(force_ft0):
			self.lta.write_memory(0x803ba, b'\x00\x00') # STFT
			self.lta.write_memory(0x817ac, b'\x00\x00') # Idle LTFT (us)
			self.lta.write_memory(0x817ae, b'\x80\x80') # LTFT low/high flow zones (offset-128)
		if(force_os0):
			self.lta.write_memory(0x817b0, b'\x00\x00\x00\x00\x00\x00\x00\x00')

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
			lambda: self.read_u8(0x80116) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 110
		),
		SimpleGauge(parent,
			"Engine air",
			lambda: self.read_u8(0x80118) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 70
		),
		SimpleGauge(parent,
			"MAF Accumulated",
			lambda: self.read_u16(0x8018a),
			"{:.1f} g",
			0, 1000
		),
		SimpleGauge(parent,
			"TPS",
			lambda: self.read_u8(0x80134) * 100 / 255,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Tip In",
			lambda: self.read_u32(0x80342),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Tip Out",
			lambda: self.read_u32(0x80346),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Injection Time",
			lambda: self.read_u32(0x808b8),
			"{:d} us",
			0, 14285
		),
		SimpleGauge(parent,
			"Learn Dead Time",
			lambda: self.read_i16(0x817ac),
			"{:d} us",
			-100, 100
		),
		SimpleGauge(parent,
			"STFT",
			lambda: self.read_i16(0x803ba) / 20,
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"LTFT",
			lambda: self.read_i16(0x803d6) / 10,
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
			lambda: self.read_i16(0x8026c) / 4,
			"{:.2f} °",
			-10, 50
		),
		SimpleGauge(parent,
			"Octane Scaler",
			[lambda: self.read_u16(0x817b0 + 0) / 655.36,
			lambda: self.read_u16(0x817b0 + 2) / 655.36,
			lambda: self.read_u16(0x817b0 + 4) / 655.36,
			lambda: self.read_u16(0x817b0 + 6) / 655.36],
			"{:.1f} %",
			0, 100
		)
	]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[10000/(int(v)*50) if v else 0 for v in self.lta.read_memory(0x84bf4+(i*32), 32)] for i in range(32)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x84bf4+(y*32)+x, max(0, min(255, round(200/value))).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x84bb4, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x84bd4, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x85a7c+(i*32), 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x85a7c+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x85a3c, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x85a5c, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Advance Low Cam",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x84454+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x84454+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x84434, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x84444, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Advance High Cam",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x85054+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x85054+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x85034, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x85044, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"AFR Target",
			lambda: [[int(v)/20+5 for v in self.lta.read_memory(0x87a46+(i*16), 16)] for i in range(16)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x87a46+(y*16)+x,int((value-5)*20).to_bytes(1, BO_BE)),
			0.1,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x87a26, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x87a36, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Tip-In Adj. 1",
			lambda: [[int(v)*100/128 for v in self.lta.read_memory(0x84904, 16)]],
			"{:.0f}",
			lambda x,y,value:self.lta.write_memory(0x84904+x,int(value*128/100).to_bytes(1, BO_BE)),
			1.0,

			"RPM",
			lambda: [(int(v)+16)*125//4 for v in self.lta.read_memory(0x848f4, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"", lambda: [0], "{:d}", lambda: 0
		)]
