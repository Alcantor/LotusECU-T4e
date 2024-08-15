.section .data

CAL_sensor_oil_temp_scaling:
.byte	255, 255, 255, 249, 231, 217, 206, 197
.byte	189, 182, 175, 169, 164, 159, 154, 149
.byte	144, 140, 135, 131, 127, 122, 118, 113
.byte	108, 103,  98,  92,  85,  77,  67,  51, 3
CAL_sensor_oil_pressure_gain:
.short	12500
CAL_sensor_oil_pressure_offset:
.short	-1250

.section .bss

.lcomm	oil_temp,	1 # u8_temp_1-40c
.lcomm	oil_pressure,	2 # i16_pressure_mbar

.section .text
.globl _start, hook_loop, hook_OBD_mode_0x01

_start:
hook_loop:
	bl	obdoil
	ba	hook_loop_continue

hook_OBD_mode_0x01:
	# %r30 is index in obd_req
	# %r31 is index in obd_resp

	# Store current request byte in %r3
	lis	%r3, obd_req@ha
	addi	%r3, %r3, obd_req@l
	lbzx	%r3, %r3, %r30

	# Store pointer to response array in %r4
	# Store current pointer to response byte in %r5
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r5, %r4, %r31

	# Branching
	cmplwi	%r3, 0x20
	beq	OBD_mode_0x01_pid_0x20
	cmplwi	%r3, 0x40
	beq	OBD_mode_0x01_pid_0x40
	cmplwi	%r3, 0x5C
	beq	OBD_mode_0x01_pid_0x5C
	cmplwi	%r3, 0x23
	beq	OBD_mode_0x01_pid_0x23
	
	# Mask %r30 (Erase by patch in original code)
	rlwinm	%r0, %r30, 0,24,31
	ba	hook_OBD_mode_0x01_continue

OBD_mode_0x01_pid_0x20:
	# Available PID 0x21-0x40
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r5)

	lis	%r3, 0xA0062001@ha
	addi	%r3, %r3, 0xA0062001@l
	stw	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x40:
	# Available PID 0x41-0x60
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r5)

	lis	%r3, 0x6AC00010@ha
	addi	%r3, %r3, 0x6AC00010@l
	stw	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump
	
OBD_mode_0x01_pid_0x23:
	# Fuel Pressure, but we use it for oil.
	addi	%r31, %r31, 3 # Answer 3 bytes
	stb	%r3, 0(%r5)

	lis	%r3, oil_pressure@ha
	lha	%r3, oil_pressure@l(%r3)

	# Convert and do not allow negative values!
	li	%r0, 100
	divw	%r3, %r3, %r0
	cmpwi	%r3, 0
	bge	pres_gt0
	li	%r3, 0
pres_gt0:
	sth	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x5C:
	# Oil temperature
	addi	%r31, %r31, 2 # Answer 2 bytes
	stb	%r3, 0(%r5)

	lis	%r3, oil_temp@ha
	lbz	%r3, oil_temp@l(%r3)

	stb	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump

obdoil:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Oil temperature scaling
	li	%r3, 3
	lis	%r4, sensor_adc_oil_temp@ha
	lhz	%r4, sensor_adc_oil_temp@l(%r4)
	lis	%r5, CAL_sensor_oil_temp_scaling@ha
	addi	%r5, %r5, CAL_sensor_oil_temp_scaling@l
	bl	lookup_2D_uint8_interpolated_noaxis
	lis	%r4, oil_temp@ha
	stb	%r3, oil_temp@l(%r4)

	# Oil pressure scaling
	lis	%r3, sensor_adc_oil_pressure_analog@ha
	lhz	%r3, sensor_adc_oil_pressure_analog@l(%r3)
	lis	%r4, CAL_sensor_oil_pressure_gain@ha
	lhz	%r4, CAL_sensor_oil_pressure_gain@l(%r4)
	lis	%r5, CAL_sensor_oil_pressure_offset@ha
	lhz	%r5, CAL_sensor_oil_pressure_offset@l(%r5)
	mullw	%r6, %r3, %r4
	srawi	%r6, %r6, 10
	addze	%r6, %r6
	add	%r6, %r6, %r5
	lis	%r7, oil_pressure@ha
	sth	%r6, oil_pressure@l(%r7)

	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr

