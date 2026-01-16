import random
from lib.gui_tuner import MapTable, SimpleGauge

class TunerDefinition:
	def __init__(self, lta):
		self.lta = lta
		self.name = "DUMMY-Definition"
		self.engine_speed = 4000
		self.load = 200

	def check(self):
		return False

	def loop(self, force_ft0, force_os0):
		self.engine_speed += random.randint(-50, 50)
		self.engine_speed = sorted([0, self.engine_speed, 8000])[1]
		self.load += random.randint(-5, 5)
		self.load = sorted([0, self.load, 640])[1]

	def impcal(self, filename):
		pass

	def expcal(self, filename):
		pass

	def gauges(self, parent):
		return [
		SimpleGauge(parent,
			"Engine Speed",
			lambda: self.engine_speed,
			"{:d} rpm",
			0, 8400
		),
		SimpleGauge(parent,
			"Engine Load",
			lambda: self.load,
			"{:d} mg/str.",
			0, 640
		)]

	def maps(self, parent):
		return [
		MapTable(parent,
			"Efficiency",
			lambda: [[x*y for x in range(32)] for y in range(32)],
			"{:.0f}",
			lambda x,y,value:None,
			1.0,

			"RPM",
			lambda: [(i+1)*250 for i in range(32)],
			"{:d}",
			lambda: self.engine_speed,

			"Load",
			lambda: [(i+1)*20 for i in range(32)],
			"{:d}",
			lambda: self.load
		),
		MapTable(parent,
			"Ignition High Cam",
			lambda: [[x*y for x in range(8)] for y in range(8)],
			"{:.0f}",
			lambda x,y,value:None,
			1.0,

			"RPM",
			lambda: [(i+1)*1000 for i in range(8)],
			"{:d}",
			lambda: self.engine_speed,

			"Load",
			lambda: [(i+1)*80 for i in range(8)],
			"{:d}",
			lambda: self.load
		)]
