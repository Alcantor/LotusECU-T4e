CALENTRY CAL_sensor_oil_temp_scaling
	.byte	255, 255, 255, 249, 231, 217, 206, 197
	.byte	189, 182, 175, 169, 164, 159, 154, 149
	.byte	144, 140, 135, 131, 127, 122, 118, 113
	.byte	108, 103,  98,  92,  85,  77,  67,  51, 3
CALENTRY CAL_sensor_oil_temp_reactivity
	.byte	0x02
CALENTRY CAL_sensor_oil_pressure_gain
	.short	12500
CALENTRY CAL_sensor_oil_pressure_offset
	.short	-1250
CALENTRY CAL_sensor_oil_pressure_reactivity
	.byte	0x40
CALENTRY CAL_obd_P0522_threshold
	.short	50   # ~0.24V (below 0.5V valid range)
CALENTRY CAL_obd_P0523_threshold
	.short	973  # ~4.76V (above 4.5V valid range)
CALENTRY CAL_obd_P0522
	.byte	0x51
CALENTRY CAL_obd_P0523
	.byte	0x51
# Padding
	.byte	0xFF, 0xFF, 0xFF
