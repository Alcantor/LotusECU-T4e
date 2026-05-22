CALENTRY CAL_sensor_ethanol_temp_reactivity
	.byte 0x02
CALENTRY CAL_sensor_ethanol_content_reactivity
	.byte 0x04
CALENTRY CAL_sensor_ethanol_engine_speed_limit
	.byte 0x70 # 4000rpm
CALENTRY CAL_sensor_ethanol_engine_load_limit
	.byte 0x96 # 600mg/stroke
CALENTRY CAL_sensor_ethanol_temp_fallback
	.byte 96 # 20°C
CALENTRY CAL_sensor_ethanol_content_fallback
	.byte 102 # 40 %
CALENTRY CAL_ethanol_ign_adv_adj1
	.space 16
CALENTRY CAL_ethanol_ign_adv_high_cam_base
	.space 64
CALENTRY CAL_ethanol_injtip_in_adj1
	.space 16
CALENTRY CAL_ethanol_injtip_out_adj1
	.space 16
CALENTRY CAL_ethanol_inj_efficiency
	.space 1024
CALENTRY CAL_ethanol_inj_time_adj3
	.space 256
CALENTRY CAL_ethanol_inj_time_adj_cranking
	.space 16
CALENTRY CAL_ethanol_ign_adv_low_cam_base
	.space 1024
CALENTRY CAL_ethanol_scale_1_low
	.byte 0 # 0 %
CALENTRY CAL_ethanol_scale_1_high
	.byte 216 # 85 %
CALENTRY CAL_ethanol_scale_2_low
	.byte 12 # 5 %
CALENTRY CAL_ethanol_scale_2_high
	.byte 102 # 40 %
CALENTRY CAL_obd_P0176
	.byte 0x51
CALENTRY CAL_obd_P0177
	.byte 0x51
