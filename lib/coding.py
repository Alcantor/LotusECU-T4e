import os, sys
from lib.crc import CRC16Reflect

# Mode 0x22 PID 0x0263 return 0x1C004 in little endian
# Mode 0x22 PID 0x0264 return 0x1C000 in little endian
#
# Send CAN frame with 8 bytes variant in big endian to:
#
#	0x500 - Instruments Cluster
#	0x501 - ?
#	0x502 - ECU
#	0x503 - ?
#	0x504 - ?
#	0x505 - ?

# Some constants
BO_BE = 'big'
CHARSET = 'ISO-8859-15'
FALSE_TRUE = ("False", "True")

# Coding (coding.bin) Format:
#
#	 8 Bytes   - Variant
#	17 Bytes   - VIN
#	 7 Bytes   - 7x 0xFF
#	32 Bytes   - Model
#	 2 Bytes   - 16 Bits CRC
#
class Coding():
	options = (
		# Shift, Mask, Name, Options
		(63,   1, "Oil Cooling System", ("Standard", "Additional")),
		# Bit 62 not used
		(60,   3, "Heating Ventilation Air Conditioning", ("None", "Heater Only", "Air Conditioning", "Climate Control")),
		(57,   7, "Cruise System", ("None","Basic","Adaptive")),
		(54,   7, "Traction Control Level", ("None", "Basic TC", "TC + Drag Torque Control", "ESP")),
		(53,   1, "Differential type", ("Open","LSD")),
		(52,   1, "Wheel Profile", ("18/19 inch","19/20 inch")),
		(49,   7, "Number of Gears", ("1","2","3","4","5","6","7","8")),
		(48,   1, "Close Ratio Gearset", FALSE_TRUE),
		(45,   7, "Transmission Type", ("Manual","Auto","MMT")),
		(44,   1, "Airbag System", ("True", "False")),
		(43,   1, "Speed Units", ("MPH","KPH")),
		(36, 127, "Fuel Tank Capacity", None),
		(35,   1, "Rear Fog Fitted", FALSE_TRUE),
		(34,   1, "Japan Seatbelt Warning", FALSE_TRUE),
		(33,   1, "Symbol Display", ("ECE(ROW)","SAE(FED)")),
		(32,   1, "Driver Position", ("LHD","RHD")),
		(31,   1, "Race Button", FALSE_TRUE),
		(30,   1, "Exhaust Bypass Valve Override", FALSE_TRUE),
		(29,   1, "DPM Switch", FALSE_TRUE),
		(28,   1, "Seat Heaters", FALSE_TRUE),
		(27,   1, "Exhaust Silencer Bypass Valve", FALSE_TRUE),
		(26,   1, "Auxiliary Cooling Fan", FALSE_TRUE),
		(25,   1, "Speed Alert Buzzer", FALSE_TRUE),
		(24,   1, "TC/ESP Button", FALSE_TRUE),
		(23,   1, "Sport Button", FALSE_TRUE),
		(21,   3, "Clutch Input", ("None","Switch","Potentiometer")),
		(20,   1, "Recirc Valve", FALSE_TRUE),
		(19,   1, "MT Cooler", FALSE_TRUE),
		(18,   1, "Fuel Pump", ("Relay", "PWM")),
		# Bit 17-16 not used
		(15,   1, "Body Control Module", FALSE_TRUE),
		(14,   1, "Transmission Control Unit", FALSE_TRUE),
		(13,   1, "Tyre Pressure Monitoring System", FALSE_TRUE),
		(12,   1, "Steering Angle Sensor", FALSE_TRUE),
		(11,   1, "Yaw Rate Sensor", FALSE_TRUE),
		(10,   1, "Instrument Cluster", ("MY08","MY11/12")),
		( 9,   1, "Anti-Lock Braking System", FALSE_TRUE),
		( 8,   1, "Launch Mode", FALSE_TRUE),
		( 7,   1, "Race Mode", FALSE_TRUE),
		( 6,   1, "Speed Limiter", FALSE_TRUE),
		( 5,   1, "Reverse Camera", FALSE_TRUE),
		( 4,   1, "Powerfold Mirrors", FALSE_TRUE),
		# Bit 3-2 not used
		( 1,   1, "Central Door Locking", FALSE_TRUE),
		( 0,   1, "Oil Sump System", ("Standard","Upgrade"))
	)

	def __init__(self):
		self.data = memoryview(bytearray(0x42))

	def read_file(self, file):
		with open(file, 'rb') as f:
			#f.seek(0x1C000)
			self.data = memoryview(bytearray(f.read()))

	def write_file(self, file):
		with open(file, 'wb') as f: f.write(self.data)

	def get_variant(self):
		return int.from_bytes(self.data[0:8], BO_BE)

	def set_variant(self, code):
		self.data[0:8] = code.to_bytes(8, BO_BE)

	def _swap_32(v):
		return (v >> 32) | ((v & 0xFFFFFFFF) << 32)

	def _swap_endian_64(v):
		v = ((v << 32) & 0xFFFFFFFF00000000) | ((v >> 32) & 0x00000000FFFFFFFF)
		v = ((v << 16) & 0xFFFF0000FFFF0000) | ((v >> 16) & 0x0000FFFF0000FFFF)
		v = ((v << 8) & 0xFF00FF00FF00FF00) | ((v >> 8) & 0x00FF00FF00FF00FF)
		return v

	def get_variant_lotus(self):
		return Coding._swap_32(self.get_variant())

	def set_variant_lotus(self, code):
		self.set_variant(Coding._swap_32(code))

	def get_variant_little(self):
		return Coding._swap_endian_64(self.get_variant())

	def set_variant_little(self, code):
		self.set_variant(Coding._swap_endian_64(code))

	def get_vin(self):
		return str(self.data[8:25], CHARSET).rstrip(" \x00")

	def get_model(self):
		return str(self.data[32:64], CHARSET).rstrip(" \x00")

	def get_crc(self):
		return int.from_bytes(self.data[64:66], BO_BE)

	def set_crc(self, crc):
		self.data[64:66] = crc.to_bytes(2, BO_BE)

	def compute_crc(self):
		crc = CRC16Reflect(0x8005, initvalue=0x0000)
		crc.update(self.data[0:64])
		return crc.get()

	def __str__(self):
		fmt = """
Coding:

{:s}
{:38s}: {:s}
{:38s}: {:s}
{:38s}: 0x{:04X}
{:38s}: 0x{:04X}

{:38s}: 0x{:016X}
{:38s}: 0x{:016X}
{:38s}: 0x{:016X}
"""
		txt = ""
		variant = self.get_variant()
		for o in Coding.options:
			value = (variant >> o[0]) & o[1]
			text = o[3][value] if(o[3] != None and value < len(o[3])) else str(value)
			txt += "{:38s}: {:s}\n".format(o[2], text)
		return fmt.format(
			txt,
			"VIN", self.get_vin(),
			"MODEL", self.get_model(),
			"CRC", self.compute_crc(),
			"Stored CRC", self.get_crc(),
			"Variant (Big Endian)", self.get_variant(),
			"Variant (Lotus Tools)", self.get_variant_lotus(),
            "Variant (Little Endian)", self.get_variant_little()
		)

if __name__ == "__main__":
	print("Tool to decode the Lotus T6 coding.bin.\n")
	cod = Coding()
	if  (len(sys.argv) >= 3 and sys.argv[1] == "file"):
		cod.read_file(sys.argv[2])
		print(cod)
	elif(len(sys.argv) >= 3 and sys.argv[1] == "big"):
		cod.set_variant(int(sys.argv[2], 0))
		print(cod)
	elif(len(sys.argv) >= 3 and sys.argv[1] == "lotus"):
		cod.set_variant_lotus(int(sys.argv[2], 0))
		print(cod)
	elif(len(sys.argv) >= 3 and sys.argv[1] == "little"):
		cod.set_variant_little(int(sys.argv[2], 0))
		print(cod)
	else:
		prog = os.path.basename(sys.argv[0])
		print("usage:")
		print(f"\t{prog} file COD_FILE")
		print(f"\t{prog} big VALUE")
		print(f"\t{prog} lotus VALUE")
		print(f"\t{prog} little VALUE")
