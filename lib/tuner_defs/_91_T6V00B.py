from lib.gui_tuner import MapTable, SimpleGauge

BO_BE = 'big'

class TunerDefinition:
	IDENT = b"T6-V000B 08/06/2017 Lotus Eng"

	def __init__(self, lta):
		self.lta = lta
		self.name = "T6-V000B"
		self.engine_speed_2 = 0
		self.load_1 = 0
		self.afr_t = 10

	def check(self):
		return self.lta.read_memory(0x000cb158, 29) == TunerDefinition.IDENT

	def read_u8(self, address):
		return int.from_bytes(self.lta.read_memory(address, 1), BO_BE)

	def read_u16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE)

	def read_i16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE, signed=True)

	def read_u32(self, address):
		return int.from_bytes(self.lta.read_memory(address, 4), BO_BE)

	def impcal(self, filename):
		self.lta.upload(0x40008e24, filename)
		self.lta.verify(0x40008e24, filename)

	def expcal(self, filename):
		self.lta.download(0x40008e24, 0x61da, filename)
		self.lta.verify(0x40008e24, filename)

	def loop(self, force_ft0, force_os0):
		self.engine_speed_2 = self.read_u16(0x4000160a)
		self.load_1 = self.read_u32(0x40001a38)
		self.afr_t = self.read_u16(0x4000181c) / 100
		if(force_ft0):
			self.lta.write_memory(0x40001b8c, b'\x00\x00') # STFT Bank 1
			self.lta.write_memory(0x40001b8e, b'\x00\x00') # STFT Bank 2
			self.lta.write_memory(0x40001b98, b'\x00\x00') # LTFT Bank 1
			self.lta.write_memory(0x40001b9a, b'\x00\x00') # LTFT Bank 2
		if(force_os0):
			self.lta.write_memory(0x400031b4, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

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
			lambda: self.read_u8(0x400016de) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 110
		),
		SimpleGauge(parent,
			"Intake air",
			lambda: self.read_u8(0x400016e2) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 70
		),
		SimpleGauge(parent,
			"MAF Accumulated",
			lambda: self.read_u16(0x4000155a),
			"{:d} g",
			0, 1000
		),
		SimpleGauge(parent,
			"TPS",
			lambda: self.read_u8(0x400016ee) * 100 / 255,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Fuel Pressure",
			lambda: self.read_u16(0x40001798),
			"{:d} mbar",
			0, 6000
		),
		SimpleGauge(parent,
			"Injection Time",
			lambda: self.read_u16(0x400017f8),
			"{:d} us",
			0, 16666
		),
		SimpleGauge(parent,
			"STFT",
			[lambda: self.read_i16(0x40001b8c) / 20,
			 lambda: self.read_i16(0x40001b8e) / 20],
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"LTFT",
			[lambda: self.read_i16(0x40001b98) / 20,
			 lambda: self.read_i16(0x40001b9a) / 20],
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
			lambda: self.read_i16(0x400017b0) / 4,
			"{:.2f} °",
			-10, 50
		),
		SimpleGauge(parent,
			"Octane Scaler",
			[lambda: self.read_u16(0x400031b4 + 0) / 655.36,
			 lambda: self.read_u16(0x400031b4 + 2) / 655.36,
			 lambda: self.read_u16(0x400031b4 + 4) / 655.36,
			 lambda: self.read_u16(0x400031b4 + 6) / 655.36,
			 lambda: self.read_u16(0x400031b4 + 8) / 655.36,
			 lambda: self.read_u16(0x400031b4 + 10) / 655.36],
			"{:.1f} %",
			0, 100
		)
	]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[int(v)/2 for v in self.lta.read_memory(0x40009e0a+(i*32), 32)] for i in range(32)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x40009e0a+(y*32)+x, int(value*2).to_bytes(1, BO_BE)),
			0.5,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x40009dca, 32)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x40009dea, 32)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition (Non-IPS)",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x4000abaa+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000abaa+(y*20)+x, int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000ab82, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000ab96, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition (IPS)",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x4000d7ec+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000d7ec+(y*20)+x, int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000d7c4, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000d7d8, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Intake",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x4000966a+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000966a+(y*16)+x, int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000964a, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000965a, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Exhaust",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x4000a26a+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000a26a+(y*16)+x, int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000a24a, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000a25a, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"AFR Target",
			lambda: [[int(v)/20+5 for v in self.lta.read_memory(0x4000a9f2+(i*20), 20)] for i in range(20)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x4000a9f2+(y*20)+x, int((value-5)*20).to_bytes(1, BO_BE)),
			0.1,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000a9ca, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*23//5 for v in self.lta.read_memory(0x4000a9de, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Inj Flow Rate",
			lambda: [[int.from_bytes(self.lta.read_memory(0x40009024, 2), BO_BE)]],
			"{:.0f}",
			lambda x,y,value:self.lta.write_memory(0x40009024, int(value).to_bytes(2, BO_BE)),
			1.0,

			"", lambda: [0], "{:d}", lambda: 0,
			"", lambda: [0], "{:d}", lambda: 0
		)]
