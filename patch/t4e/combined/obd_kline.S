# Mode 1 PID Mask
.set OBD_PID_0x00_MASK, 0xFE1FB813
.set OBD_PID_0x20_MASK, 0x80062001
.set OBD_PID_0x40_MASK, 0x6AC00000

.section .text
.global hook_OBD_mode_0x01, hook_OBD_mode_0x22

hook_OBD_mode_0x01:
	# %r3 is the obd pid

	# Branching
	cmplwi	%r3, 0x00
	beq	OBD_mode_0x01_pid_0x00
	cmplwi	%r3, 0x20
	beq	OBD_mode_0x01_pid_0x20
	cmplwi	%r3, 0x40
	beq	OBD_mode_0x01_pid_0x40
.ifdef OBDOIL
.set OBD_PID_0x00_MASK, OBD_PID_0x00_MASK | 1<<(0x20-0x0B)
.set OBD_PID_0x40_MASK, OBD_PID_0x40_MASK | 1<<(0x60-0x5C)
	cmplwi	%r3, 0x0B
	beq	OBD_mode_0x01_pid_0x0B
	cmplwi	%r3, 0x5C
	beq	OBD_mode_0x01_pid_0x5C
.endif
.ifdef FLEXFUEL
.set OBD_PID_0x40_MASK, OBD_PID_0x40_MASK | 1<<(0x60-0x52)
	cmplwi	%r3, 0x52
	beq	OBD_mode_0x01_pid_0x52
.endif
.ifdef WIDEBAND
.set OBD_PID_0x20_MASK, OBD_PID_0x20_MASK | 1<<(0x40-0x24)
	cmplwi	%r3, 0x24
	beq	OBD_mode_0x01_pid_0x24
.endif
	# Copy %r3 (Erase by patch in original code)
	or	%r31, %r3, %r3
	ba	hook_OBD_mode_0x01_continue

# Available PIDs
OBD_mode_0x01_pid_0x00:
	lis	%r4, OBD_PID_0x00_MASK@ha
	addi	%r4, %r4, OBD_PID_0x00_MASK@l
	b	OBD_mode_0x01_send_uint32
OBD_mode_0x01_pid_0x20:
	lis	%r4, OBD_PID_0x20_MASK@ha
	addi	%r4, %r4, OBD_PID_0x20_MASK@l
	b	OBD_mode_0x01_send_uint32
OBD_mode_0x01_pid_0x40:
	lis	%r4, OBD_PID_0x40_MASK@ha
	addi	%r4, %r4, OBD_PID_0x40_MASK@l
	b	OBD_mode_0x01_send_uint32

OBD_mode_0x01_send_uint32:
	lis	%r5, obd_resp@ha
	addi	%r5, %r5, obd_resp@l

	# Header
	li	%r6, 0x48
	stb	%r6, 0(%r5)
	li	%r6, 0x6B
	stb	%r6, 1(%r5)
	li	%r6, 0x10
	stb	%r6, 2(%r5)
	li	%r6, 0x41
	stb	%r6, 3(%r5)
	stb	%r3, 4(%r5)

	# Value
	stw	%r4, 5(%r5)

	# Checksum
	li	%r6, 0x104 # 0x104 = 0x48+0x6B+0x10+0x41
	add	%r6, %r6, %r3
	rlwinm	%r3, %r4,  8,24,31
	add	%r6, %r6, %r3
	rlwinm	%r3, %r4, 16,24,31
	add	%r6, %r6, %r3
	rlwinm	%r3, %r4, 24,24,31
	add	%r6, %r6, %r3
	rlwinm	%r3, %r4,  0,24,31
	add	%r6, %r6, %r3
	stb	%r6, 9(%r5)

	# Init sending variable
	li	%r4, 0x09
	lis	%r3, obd_resp_length@ha
	stb	%r4, obd_resp_length@l(%r3)
	li	%r4, 0x00
	lis	%r3, obd_resp_index@ha
	stb	%r4, obd_resp_index@l(%r3)

	# Set the first byte into SCI1 Data Register
	li	%r4, 0x48
	lis	%r3, 0x030500E@ha
	sth	%r4, 0x030500E@l(%r3)

	ba	hook_OBD_mode_0x01_jump

.ifdef OBDOIL
OBD_mode_0x01_pid_0x0B:
	# Intake manifold absolute pressure
	lis	%r4, map@ha
	lha	%r4, map@l(%r4)

	# Avoid negative numbers by clamping to 0
	cmpwi	%r4, 0
	bgt	presB_1
	li	%r4, 0
	b	presB_3
presB_1:
	# Clamp to 8-bits by limiting max to 2550 mbar (255 kPa)
	cmpwi	%r4, 2550
	blt	presB_2
	li	%r4, 255
	b	presB_3
presB_2:
	# Convert from mbar to kPa by dividing by 10 (Use reciprocal division)
	mulli	%r4, %r4, ((1<<18)/10)
	srwi	%r4, %r4, 18
presB_3:
	bl	OBD_mode_0x01_send_uint8
	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x5C:
	# Oil temperature
	lis	%r4, oil_temp@ha
	lbz	%r4, oil_temp@l(%r4)

	bl	OBD_mode_0x01_send_uint8
	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef FLEXFUEL
OBD_mode_0x01_pid_0x52:
	# Ethanol fuel %
	lis	%r4, ethanol_content@ha
	lbz	%r4, ethanol_content@l(%r4)

	bl	OBD_mode_0x01_send_uint8
	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x01_pid_0x24:
	# Wideband Lambda

	# Corrected Pre-O2 WB input (0V = 10 AFR, 5V = 20 AFR)
	lis	%r5, wb_corr_adc@ha
	lhz	%r5, wb_corr_adc@l(%r5)

	# Byte AB = (0.68 + ADC/1023*0.68) * 65536/2
	mulli	%r4, %r5, 22304 # 22304 = ((1 << 25) * 0.68 / 1023
	srwi	%r4, %r4, 10
	addi	%r4, %r4, 22282 # 22282 = ((1 << 15) * 0.68
	slwi	%r4, %r4, 16

	# Byte CD
	# CD = ADC/1023*5*65536/8 = ADC * 40.04
	mulli	%r5, %r5, 20500 # 20500 = ((1 << 25) * 40.04
	srwi	%r5, %r5, 9
	or	%r4, %r4, %r5

	bl	OBD_mode_0x01_send_uint32
	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef ACCUSUMP
	.set OILPRESSURE, 1
.endif
.ifdef OBDOIL
	.set OILPRESSURE, 1
.endif

hook_OBD_mode_0x22:
	# %r3 is the obd pid

	# Branching
.ifdef FLEXFUEL
	cmplwi	%r3, 0x0401
	beq	OBD_mode_0x22_pid_0x0401
.endif
.ifdef OILPRESSURE
	cmplwi	%r3, 0x0402
	beq	OBD_mode_0x22_pid_0x0402
.endif
.ifdef WIDEBAND
	cmplwi	%r3, 0x0403
	beq	OBD_mode_0x22_pid_0x0403
	cmplwi	%r3, 0x0404
	beq	OBD_mode_0x22_pid_0x0404
.endif
	# Copy %r3 (Erase by patch in original code)
	or	%r31, %r3, %r3
	ba	hook_OBD_mode_0x22_continue

.ifdef FLEXFUEL
OBD_mode_0x22_pid_0x0401:
	# Fuel temperature
	lis	%r4, ethanol_temp@ha
	lbz	%r4, ethanol_temp@l(%r4)
	bl	OBD_mode_0x22_send_uint8
	ba	hook_OBD_mode_0x22_jump
.endif

.ifdef OILPRESSURE
OBD_mode_0x22_pid_0x0402:
	# Oil Pressure
	lis	%r4, oil_pressure@ha
	lha	%r4, oil_pressure@l(%r4)
	bl	OBD_mode_0x22_send_uint16
	ba	hook_OBD_mode_0x22_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x22_pid_0x0403:
	# Wideband correction slope
	lis	%r4, wb_slope@ha
	lhz	%r4, wb_slope@l(%r4)
	bl	OBD_mode_0x22_send_uint16
	ba	hook_OBD_mode_0x22_jump

OBD_mode_0x22_pid_0x0404:
	# Wideband correction offset
	lis	%r4, wb_offset@ha
	lha	%r4, wb_offset@l(%r4)
	bl	OBD_mode_0x22_send_uint16
	ba	hook_OBD_mode_0x22_jump
.endif
