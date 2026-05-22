.section .bss
.global oil_temp, oil_pressure

.lcomm	oil_temp,              1, 1 # u8_temp_1-40c
.lcomm	oil_pressure,          2, 2 # i16_pressure_mbar
.lcomm	oil_temp_smooth_x,     4, 4
.lcomm	oil_pressure_smooth_x, 4, 4
.lcomm	obd_P0522_config,      1, 1 # P0522: Oil Pressure Sensor Circuit Low
.lcomm	obd_P0522_flags,       1, 1
.lcomm	obd_P0523_config,      1, 1 # P0523: Oil Pressure Sensor Circuit High
.lcomm	obd_P0523_flags,       1, 1
.lcomm	obd_obdoil_counter,    1, 1 # Dummy shared start/warm counter for obd_set_dtc

.section .text
.global obdoil_init, obdoil

obdoil_init:
	# Start with 20°C
	li	%r3, 96
	lis	%r4, oil_temp@ha
	stb	%r3, oil_temp@l(%r4)
	slwi	%r3, %r3, 8
	lis	%r4, oil_temp_smooth_x@ha
	stw	%r3, oil_temp_smooth_x@l(%r4)

	# Start with 0 mbar
	li	%r3, 0
	lis	%r4, oil_pressure@ha
	sth	%r3, oil_pressure@l(%r4)
	slwi	%r3, %r3, 8
	lis	%r4, oil_pressure_smooth_x@ha
	stw	%r3, oil_pressure_smooth_x@l(%r4)

	# Initialize OBD DTC config bytes
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l
	lbz	%r3, OFF_CAL_obd_P0522(%r12)
	lis	%r4, obd_P0522_config@ha
	stb	%r3, obd_P0522_config@l(%r4)
	lbz	%r3, OFF_CAL_obd_P0523(%r12)
	lis	%r4, obd_P0523_config@ha
	stb	%r3, obd_P0523_config@l(%r4)
	blr

obdoil:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Load CAL_base_extra into r12 for multiple uses
	# It won't be overwritten in lookup_2D_uint8_interpolated_noaxis
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l

	# Oil temperature scaling
	li	%r3, 3
	lis	%r4, sensor_adc_free_2@ha
	lhz	%r4, sensor_adc_free_2@l(%r4)
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	addi	%r5, %r12, OFF_CAL_sensor_oil_temp_scaling
	bla	lookup_2D_uint8_interpolated_noaxis

	# Smooth (low-pass filter)
	#
	# smooth = (smooth * (256 - reactivity)) / 256 + (value * reactivity) / 256
	#
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_sensor_oil_temp_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, oil_temp_smooth_x@ha
	lwz	%r6, oil_temp_smooth_x@l(%r7)
	mullw	%r6, %r6, %r5
	srwi	%r6, %r6, 8
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, oil_temp_smooth_x@ha
	stw	%r3, oil_temp_smooth_x@l(%r7)
	srwi	%r3, %r3, 8
	lis	%r4, oil_temp@ha
	stb	%r3, oil_temp@l(%r4)

	# Read raw ADC for oil pressure fault detection
	lis	%r3, sensor_adc_free_3@ha
	lhz	%r3, sensor_adc_free_3@l(%r3)

	# P0522: ADC too low (sensor shorted to ground)
	lhz	%r4, OFF_CAL_obd_P0522_threshold(%r12)
	cmplw	%r3, %r4
	blt	obdoil_p0522_set

	# P0523: ADC too high (sensor shorted to 5V)
	lhz	%r4, OFF_CAL_obd_P0523_threshold(%r12)
	cmplw	%r3, %r4
	bgt	obdoil_p0523_set

	# Oil pressure scaling
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lhz	%r4, OFF_CAL_sensor_oil_pressure_gain(%r12)
	lha	%r5, OFF_CAL_sensor_oil_pressure_offset(%r12)
	mullw	%r3, %r3, %r4
	srwi	%r3, %r3, 10
	add	%r3, %r3, %r5

	# Smooth (low-pass filter, signed)
	#
	# smooth = (smooth * (256 - reactivity)) / 256 + (value * reactivity) / 256
	#
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_sensor_oil_pressure_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, oil_pressure_smooth_x@ha
	lwz	%r6, oil_pressure_smooth_x@l(%r7)
	mullw	%r6, %r6, %r5
	srawi	%r6, %r6, 8
	addze	%r6, %r6
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, oil_pressure_smooth_x@ha
	stw	%r3, oil_pressure_smooth_x@l(%r7)
	srawi	%r3, %r3, 8
	addze	%r3, %r3
	lis	%r4, oil_pressure@ha
	sth	%r3, oil_pressure@l(%r4)

	# ADC in valid range: clear P0522 and P0523
	lis	%r3, obd_P0522_config@ha
	addi	%r3, %r3, obd_P0522_config@l
	lis	%r4, obd_P0522_flags@ha
	addi	%r4, %r4, obd_P0522_flags@l
	bla	obd_clr_dtc
	lis	%r3, obd_P0523_config@ha
	addi	%r3, %r3, obd_P0523_config@l
	lis	%r4, obd_P0523_flags@ha
	addi	%r4, %r4, obd_P0523_flags@l
	bla	obd_clr_dtc
	b	obdoil_end

obdoil_p0522_set:
	lis	%r3, obd_P0522_config@ha
	addi	%r3, %r3, obd_P0522_config@l
	lis	%r4, obd_P0522_flags@ha
	addi	%r4, %r4, obd_P0522_flags@l
	lis	%r5, obd_obdoil_counter@ha
	addi	%r5, %r5, obd_obdoil_counter@l
	mr	%r6, %r5
	li	%r7, 522
	bla	obd_set_dtc
	b	obdoil_end

obdoil_p0523_set:
	lis	%r3, obd_P0523_config@ha
	addi	%r3, %r3, obd_P0523_config@l
	lis	%r4, obd_P0523_flags@ha
	addi	%r4, %r4, obd_P0523_flags@l
	lis	%r5, obd_obdoil_counter@ha
	addi	%r5, %r5, obd_obdoil_counter@l
	mr	%r6, %r5
	li	%r7, 523
	bla	obd_set_dtc
	b	obdoil_end

obdoil_end:
	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr
