.section .bss
.global oil_temp, oil_pressure

.lcomm	oil_temp,         1, 1 # u8_temp_1-40c
.lcomm	oil_pressure,     2, 2 # i16_pressure_mbar
.lcomm	oil_temp_avg,     4, 4
.lcomm	oil_pressure_avg, 4, 4

.section .text
.global obdoil_init, obdoil

obdoil_init:
	# Start with 20°C
	li	%r3, 96
	lis	%r4, oil_temp@ha
	stb	%r3, oil_temp@l(%r4)
	slwi	%r3, %r3, 8
	lis	%r4, oil_temp_avg@ha
	stw	%r3, oil_temp_avg@l(%r4)

	# Start with 0 mbar
	li	%r3, 0
	lis	%r4, oil_pressure@ha
	sth	%r3, oil_pressure@l(%r4)
	slwi	%r3, %r3, 8
	lis	%r4, oil_pressure_avg@ha
	stw	%r3, oil_pressure_avg@l(%r4)

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
	lis	%r4, sensor_adc_free2@ha
	lhz	%r4, sensor_adc_free2@l(%r4)
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	addi	%r5, %r12, OFF_CAL_sensor_oil_temp_scaling
	bla	lookup_2D_uint8_interpolated_noaxis

	# Average
	#
	# avg = (avg * (256 - reactivity))/256 + (value * reactivity)
	#
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_sensor_oil_temp_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, oil_temp_avg@ha
	lwz	%r6, oil_temp_avg@l(%r7)
	mullw	%r6, %r6, %r5
	srwi	%r6, %r6, 8
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, oil_temp_avg@ha
	stw	%r3, oil_temp_avg@l(%r7)
	srwi	%r3, %r3, 8
	lis	%r4, oil_temp@ha
	stb	%r3, oil_temp@l(%r4)

	# Oil pressure scaling
	lis	%r3, sensor_adc_free3@ha
	lhz	%r3, sensor_adc_free3@l(%r3)
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lhz	%r4, OFF_CAL_sensor_oil_pressure_gain(%r12)
	lha	%r5, OFF_CAL_sensor_oil_pressure_offset(%r12)
	mullw	%r3, %r3, %r4
	srwi	%r3, %r3, 10
	add	%r3, %r3, %r5

	# Average (signed)
	#
	# avg = (avg * (256 - reactivity))/256 + (value * reactivity)
	#
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_sensor_oil_pressure_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, oil_pressure_avg@ha
	lwz	%r6, oil_pressure_avg@l(%r7)
	mullw	%r6, %r6, %r5
	srawi	%r6, %r6, 8
	addze	%r6, %r6
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, oil_pressure_avg@ha
	stw	%r3, oil_pressure_avg@l(%r7)
	srawi	%r3, %r3, 8
	addze	%r3, %r3
	lis	%r4, oil_pressure@ha
	sth	%r3, oil_pressure@l(%r4)

	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr
