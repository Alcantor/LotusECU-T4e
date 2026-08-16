from lib.gui_tuner import MapTable, SimpleGauge

BO_BE = 'big'

class TunerDefinition:
	IDENT = b"C1D3P000____Jun  2 2014 09:53:08V0000"

	def __init__(self, lta):
		self.lta = lta
		self.name = "Caterham Seven 485 Final Edition"
		self.engine_speed_2 = 0
		self.load_1 = 0
		self.afr_t = 10

	def check(self):
		return self.lta.read_memory(0x000a25d8, 37) == TunerDefinition.IDENT

	def read_u8(self, address):
		return int.from_bytes(self.lta.read_memory(address, 1), BO_BE)

	def read_u16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE)

	def read_i16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE, signed=True)

	def read_u32(self, address):
		return int.from_bytes(self.lta.read_memory(address, 4), BO_BE)

	def impcal(self, filename):
		self.lta.upload(0x400027d8, filename)
		self.lta.verify(0x400027d8, filename)

	def expcal(self, filename):
		self.lta.download(0x400027d8, 0x69a8, filename)
		self.lta.verify(0x400027d8, filename)

	def loop(self, force_ft0, force_os0):
		self.engine_speed_2 = self.read_u16(0x4000216e)
		self.load_1 = self.read_u32(0x40001728)
		self.afr_t = self.read_u16(0x40001558) / 100
		if(force_ft0):
			self.lta.write_memory(0x4000184a, b'\x00\x00') # STFT (inj_time_adj_by_stft)
			self.lta.write_memory(0x40001850, b'\x00\x00') # LTFT (inj_time_adj_by_ltft)
		if(force_os0):
			self.lta.write_memory(0x4000946a, b'\x00\x00\x00\x00\x00\x00\x00\x00') # octane scaler (4x u16)

	def gauges(self, parent):
		return [
		SimpleGauge(parent,
			"Engine Speed",
			lambda: self.engine_speed_2,
			"{:d} rpm",
			0, 7200
		),
		SimpleGauge(parent,
			"Engine Load",
			lambda: self.load_1,
			"{:d} mg/str.",
			60, 1153
		),
		SimpleGauge(parent,
			"Coolant",
			lambda: self.read_u8(0x4000146e) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 110
		),
		SimpleGauge(parent,
			"Intake air",
			lambda: self.read_u8(0x40001472) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 70
		),
		SimpleGauge(parent,
			"MAF Accumulated",
			lambda: self.read_u32(0x400013f0) // 1000,
			"{:d} g",
			0, 1000
		),
		SimpleGauge(parent,
			"Throttle (TPS)",
			lambda: self.read_u8(0x4000147e) * 100 / 255,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Pedal (PPS)",
			lambda: self.read_u16(0x40001bae) * 100 / 1023,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Injection Time",
			lambda: self.read_u32(0x40001548),
			"{:d} us",
			0, 16666
		),
		SimpleGauge(parent,
			"STFT",
			lambda: self.read_i16(0x4000184a) / 20,
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"LTFT",
			lambda: self.read_i16(0x40001850) / 20,
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
			lambda: self.read_i16(0x400014f0) / 4,
			"{:.2f} °",
			-10, 50
		),
		SimpleGauge(parent,
			"Octane Scaler",
			[lambda: self.read_u16(0x4000946a + 0) / 655.36,
			 lambda: self.read_u16(0x4000946a + 2) / 655.36,
			 lambda: self.read_u16(0x4000946a + 4) / 655.36,
			 lambda: self.read_u16(0x4000946a + 6) / 655.36],
			"{:.1f} %",
			0, 100
		)
	]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[int(v)/2 for v in self.lta.read_memory(0x4000379c+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000379c+(y*20)+x, int(value*2).to_bytes(1, BO_BE)),
			0.5,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x40003774, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x40003788, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition Advance",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x4000463c+(i*32), 32)] for i in range(32)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x4000463c+(y*32)+x, int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x400045fc, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000461c, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"AFR Target",
			lambda: [[int(v)/20+5 for v in self.lta.read_memory(0x4000690c+(i*16), 16)] for i in range(16)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x4000690c+(y*16)+x, int((value-5)*20).to_bytes(1, BO_BE)),
			0.05,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x400068ec, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x400068fc, 16)],
			"{:d}",
			lambda: self.load_1
		)]
