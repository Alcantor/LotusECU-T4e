.ifndef OBDOIL
CALENTRY CAL_sensor_oil_pressure_gain
	.short 12928
CALENTRY CAL_sensor_oil_pressure_offset
	.short -1293
.endif
CALENTRY CAL_accusump_X_engine_speed
	#     500, 1000, 4000, 8000   rpm
	.byte   0,   16,  112,  240 # u8_rspeed_125/4+500rpm
CALENTRY CAL_accusump
	#      1,  1.5,  3.5,  3.5   bar
	.byte 31,   46,  109,  109 # Pressure threshold in 32mbar
CALENTRY CAL_accusump_max_open_time
	.byte 30 # Maximum open time to protect the coil in u8_time_s
# Padding
	.byte	0xFF, 0xFF, 0xFF
