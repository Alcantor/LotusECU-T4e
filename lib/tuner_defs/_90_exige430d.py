from lib.gui_tuner import MapTable, SimpleGauge

# Some constants
BO_BE = 'big'

class TunerDefinition:
	IDENT = b"T6-EXIGE-430CUP-V000D 26/11/2020V0003"

	def __init__(self, lta):
		self.lta = lta
		self.name = "T6-EXIGE-430CUP-V000D"
		self.engine_speed_2 = 0
		self.load_1 = 0
		self.afr_t = 10
		self.fuel_pressure = 0

	def check(self):
		return self.lta.read_memory(0x0d0588	, 37) == TunerDefinition.IDENT

	def read_u8(self, address):
		return int.from_bytes(self.lta.read_memory(address, 1), BO_BE)

	def read_u16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE)

	def read_i16(self, address):
		return int.from_bytes(self.lta.read_memory(address, 2), BO_BE, signed=True)

	def read_u32(self, address):
		return int.from_bytes(self.lta.read_memory(address, 4), BO_BE)

	def impcal(self, filename):
		self.lta.upload(0x40008654, filename)
		self.lta.verify(0x40008654, filename)

	def expcal(self, filename):
		self.lta.download(0x40008654, 0x69aa, filename)
		self.lta.verify(0x40008654, filename)

	def loop(self, force_ft0, force_os0):
		self.engine_speed_2 = self.read_u16(0x400017da)
		self.load_1 = self.read_u32(0x40001c20)
		self.afr_t = self.read_u16(0x400019f4)/100
		self.fuel_pressure = self.read_u16(0x40001a2e)
		if(force_ft0):
			self.lta.write_memory(0x40003598, b'\x80') # LTFT Zone 1 Bank 1
			self.lta.write_memory(0x40003599, b'\x80') # LTFT Zone 2 Bank 1
			self.lta.write_memory(0x4000359a, b'\x80') # LTFT Zone 1 Bank 2
			self.lta.write_memory(0x4000359b, b'\x80') # LTFT Zone 2 Bank 2
			self.lta.write_memory(0x40001d94, b'\x00\x00') # STFT Bank 1
			self.lta.write_memory(0x40001d96, b'\x00\x00') # STFT Bank 2
			self.lta.write_memory(0x400038ac, b'\x00\x00') # Idle Trim
		if(force_os0):
			self.lta.write_memory(0x4000359c, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

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
			lambda: self.read_u8(0x400018ae) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 110
		),
		SimpleGauge(parent,
			"Engine air",
			lambda: self.read_u8(0x400018b2) * 5 / 8 - 40,
			"{:.1f} °C",
			20, 70
		),
		SimpleGauge(parent,
			"MAF Accumulated",
			lambda: self.read_u32(0x40001720) / 1000,
			"{:.1f} g",
			0, 1000
		),
		SimpleGauge(parent,
			"TPS",
			lambda: self.read_u8(0x400018be) * 100 / 255,
			"{:.1f} %",
			0, 100
		),
		SimpleGauge(parent,
			"Tip In",
			lambda: self.read_u32(0x40001bcc),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Tip Out",
			lambda: self.read_u32(0x40001bd0),
			"{:d} us",
			0, 900
		),
		SimpleGauge(parent,
			"Injection Time",
			lambda: self.read_u16(0x400019e0),
			"{:d} us",
			0, 16666
		),
		SimpleGauge(parent,
			"Fuel Pressure",
			lambda: self.fuel_pressure,
			"{:d} mbar",
			2000, 6000
		),
		SimpleGauge(parent,
			"Learn Dead Time",
			[lambda: self.read_i16(0x400035a8),
			 lambda: self.read_i16(0x400035aa)],
			"{:d} us",
			-100, 100
		),
		SimpleGauge(parent,
			"STFT",
			[lambda: self.read_i16(0x40001d94) / 20,
			 lambda: self.read_i16(0x40001d96) / 20],
			"{:.1f} %",
			-10, 10
		),
		SimpleGauge(parent,
			"LTFT",
			[lambda: self.read_i16(0x40001da0) / 20,
			 lambda: self.read_i16(0x40001da2) / 20],
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
			lambda: self.read_i16(0x40001986) / 4,
			"{:.2f} °",
			-10, 50
		),
		SimpleGauge(parent,
			"Octane Scaler",
			[lambda: self.read_u16(0x4000359c + 0) / 655.36,
			lambda: self.read_u16(0x4000359c + 2) / 655.36,
			lambda: self.read_u16(0x4000359c + 4) / 655.36,
			lambda: self.read_u16(0x4000359c + 6) / 655.36,
			lambda: self.read_u16(0x4000359c + 8) / 655.36,
			lambda: self.read_u16(0x4000359c + 10) / 655.36],
			"{:.1f} %",
			0, 100
		)
	]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[int(v)/2 for v in self.lta.read_memory(0x40009622+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x40009622+(y*20)+x,int(value*2).to_bytes(1, BO_BE)),
			0.5,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x400095fa, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000960e, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition (Non-IPS)",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x4000a3da+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000a3da+(y*20)+x,int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000a3b2, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000a3c6, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Ignition (IPS)",
			lambda: [[int(v)/4-10 for v in self.lta.read_memory(0x4000d01c+(i*20), 20)] for i in range(20)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x4000d01c+(y*20)+x,int((value+10)*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000cff4, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000d008, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Intake",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x40008e9a+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x40008e9a+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x40008e7a, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x40008e8a, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"VVT Exhaust",
			lambda: [[int(v)/4 for v in self.lta.read_memory(0x40009a9a+(i*16), 16)] for i in range(16)],
			"{:.1f}",
			lambda x,y,value:self.lta.write_memory(0x40009a9a+(y*16)+x,int(value*4).to_bytes(1, BO_BE)),
			0.25,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x40009a7a, 16)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x40009a8a, 16)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"AFR Target",
			lambda: [[int(v)/20+5 for v in self.lta.read_memory(0x4000a222+(i*20), 20)] for i in range(20)],
			"{:.2f}",
			lambda x,y,value:self.lta.write_memory(0x4000a222+(y*20)+x,int((value-5)*20).to_bytes(1, BO_BE)),
			0.1,

			"RPM",
			lambda: [int(v)*125//4+500 for v in self.lta.read_memory(0x4000a1fa, 20)],
			"{:d}",
			lambda: self.engine_speed_2,

			"Load",
			lambda: [int(v)*4 for v in self.lta.read_memory(0x4000a20e, 20)],
			"{:d}",
			lambda: self.load_1
		),
		MapTable(parent,
			"Inj Flow Rate",
			lambda: [[int.from_bytes(self.lta.read_memory(0x4000e178+x*2, 2), BO_BE) for x in range(16)]],
			"{:.0f}",
			lambda x,y,value:self.lta.write_memory(0x4000e178+x*2, int(value).to_bytes(2, BO_BE)),
			1.0,

			"Pressure mbar",
			lambda: [int.from_bytes(self.lta.read_memory(0x4000e168+x*2, 2), BO_BE) for x in range(16)],
			"{:d}",
			lambda: self.fuel_pressure,

			"", lambda: [0], "{:d}", lambda: 0
		)]
