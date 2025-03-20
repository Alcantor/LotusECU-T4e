.section .bss
.global oil_pressure

.ifndef OBDOIL
.lcomm	oil_pressure, 2, 2 # i16_pressure_mbar
.endif
.lcomm	timer,        2, 2 # u16_time_5ms

.section .text
.global accusump_init, accusump, accusump_5ms

accusump_init:
	# Initialize the timer to the value of the calibration
	lis	%r3, CAL_base_extra@ha
	addi	%r3, %r3, CAL_base_extra@l
	lbz	%r3, OFF_CAL_accusump_max_open_time(%r3)
	mulli	%r3, %r3, 200
	lis	%r4, timer@ha
	sth	%r3, timer@l(%r4)
	blr

accusump:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Load CAL_base_extra into r12 for multiple uses
	# It won't be overwritten in lookup_2D_uint8_interpolated
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l

.ifndef OBDOIL
	# Oil pressure scaling
	lis	%r3, sensor_adc_oil_pressure@ha
	lhz	%r3, sensor_adc_oil_pressure@l(%r3)
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lhz	%r4, OFF_CAL_sensor_oil_pressure_gain(%r12)
	lha	%r5, OFF_CAL_sensor_oil_pressure_offset(%r12)
	mullw	%r3, %r3, %r4
	srwi	%r3, %r3, 10
	add	%r3, %r3, %r5
	lis	%r4, oil_pressure@ha
	sth	%r3, oil_pressure@l(%r4)
.endif

	# OBD Override
	lis	%r3, OBD_mode_0x2F_state@ha
	lbz	%r3, OBD_mode_0x2F_state@l(%r3)
	cmplwi	%r3, 0x16
	bne	accusump_normal
	lis	%r3, OBD_mode_0x2F_value@ha
	lbz	%r3, OBD_mode_0x2F_value@l(%r3)
	cmplwi	%r3, 0
	beq	accusump_close
	b	accusump_open

accusump_normal:
	# Close the accusump if ignition is off
	lis	%r3, shutdown_flags@ha
	lhz	%r3, shutdown_flags@l(%r3)
	rlwinm	%r3, %r3, 0,31,31
	cmpwi	%r3, 0
	beq	accusump_close_reset_timer

	# Compare oil pressure
	li	%r3, 4
	lis	%r4, engine_speed_3@ha
	lbz	%r4, engine_speed_3@l(%r4)
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	addi	%r5, %r12, OFF_CAL_accusump
	addi	%r6, %r12, OFF_CAL_accusump_X_engine_speed
	bla	lookup_2D_uint8_interpolated
	slwi	%r3, %r3, 5 # Multiply by 32
	lis	%r4, oil_pressure@ha
	lha	%r4, oil_pressure@l(%r4)
	cmpw	%r4, %r3
	bge	accusump_close_reset_timer

accusump_open_with_timer:
	# If the time is out, close the accusump
	lis	%r3, timer@ha
	lhz	%r3, timer@l(%r3)
	cmplwi	%r3, 0
	beq	accusump_close

accusump_open:
	# Open accusump
	lis	%r3, L9822E_outputs@ha
	lbz	%r4, L9822E_outputs@l(%r3)
	ori	%r4, %r4, 0x40
	#lis	%r3, L9822E_outputs@ha
	stb	%r4, L9822E_outputs@l(%r3)
	b	accusump_return

accusump_close_reset_timer:
	# Reset the timer to the value of the calibration
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r3, OFF_CAL_accusump_max_open_time(%r12)
	mulli	%r3, %r3, 200
	lis	%r4, timer@ha
	sth	%r3, timer@l(%r4)

accusump_close:
	# Close accusump
	lis	%r3, L9822E_outputs@ha
	lbz	%r4, L9822E_outputs@l(%r3)
	rlwinm	%r4, %r4, 0,26,24
	#lis	%r3, L9822E_outputs@ha
	stb	%r4, L9822E_outputs@l(%r3)

accusump_return:
	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr

accusump_5ms:
	# Decrement the timer every 5ms
	# It's ok to use r3, r4 and r5 here.
	lis	%r3, timer@ha
	lhz	%r4, timer@l(%r3)
	cmplwi	%r4, 0
	beq	timeout
	subi	%r4, %r4, 1
	#lis	%r3, timer@ha
	sth	%r4, timer@l(%r3)
timeout:
	# Load 10 (Erase by patch in original code)
	li	%r5, 10
	blr
