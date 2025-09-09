# Mode 1 PID Mask
.set OBD_PID_0x00_MASK, 0xFE1FB813
.set OBD_PID_0x20_MASK, 0x80062001
.set OBD_PID_0x40_MASK, 0x6AC00000

.section .text
.global hook_OBD_mode_0x01, hook_OBD_mode_0x22

hook_OBD_mode_0x01:
	# %r30 is index in obd_req
	# %r31 is index in obd_resp

	# Store current request byte in %r3
	lis	%r3, obd_req@ha
	addi	%r3, %r3, obd_req@l
	lbzx	%r3, %r3, %r30

	# Store current pointer to response byte in %r4
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r4, %r4, %r31

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
	# Mask %r30 (Erase by patch in original code)
	rlwinm	%r0, %r30, 0,24,31
	ba	hook_OBD_mode_0x01_continue

# Available PIDs
OBD_mode_0x01_pid_0x00:
	lis	%r5, OBD_PID_0x00_MASK@ha
	addi	%r5, %r5, OBD_PID_0x00_MASK@l
	b	OBD_mode_0x01_mask
OBD_mode_0x01_pid_0x20:
	lis	%r5, OBD_PID_0x20_MASK@ha
	addi	%r5, %r5, OBD_PID_0x20_MASK@l
	b	OBD_mode_0x01_mask
OBD_mode_0x01_pid_0x40:
	lis	%r5, OBD_PID_0x40_MASK@ha
	addi	%r5, %r5, OBD_PID_0x40_MASK@l
	b	OBD_mode_0x01_mask
OBD_mode_0x01_mask:
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r4)
	stw	%r5, 1(%r4)
	ba	hook_OBD_mode_0x01_jump

.ifdef OBDOIL
OBD_mode_0x01_pid_0x0B:
	# Intake manifold absolute pressure
	addi	%r31, %r31, 2 # Answer 2 bytes
	stb	%r3, 0(%r4)

	lis	%r3, map@ha
	lha	%r3, map@l(%r3)

	# Avoid negative numbers by clamping to 0
	cmpwi	%r3, 0
	bgt	presB_1
	li	%r3, 0
	b	presB_3
presB_1:
	# Clamp to 8-bits by limiting max to 2550 mbar (255 kPa)
	cmpwi	%r3, 2550
	blt	presB_2
	li	%r3, 255
	b	presB_3
presB_2:
	# Convert from mbar to kPa by dividing by 10 (Use reciprocal division)
	mulli	%r3, %r3, ((1<<18)/10)
	srwi	%r3, %r3, 18
presB_3:
	stb	%r3, 1(%r4)
	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x5C:
	# Oil temperature
	addi	%r31, %r31, 2 # Answer 2 bytes
	stb	%r3, 0(%r4)

	lis	%r3, oil_temp@ha
	lbz	%r3, oil_temp@l(%r3)

	stb	%r3, 1(%r4)

	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef FLEXFUEL
OBD_mode_0x01_pid_0x52:
	# Ethanol fuel %
	addi	%r31, %r31, 2 # Answer 2 bytes
	stb	%r3, 0(%r4)

	lis	%r3, ethanol_content@ha
	lbz	%r3, ethanol_content@l(%r3)

	stb	%r3, 1(%r4)

	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x01_pid_0x24:
	# Wideband Lambda
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r4)

	# Corrected Pre-O2 WB input (0V = 10 AFR, 5V = 20 AFR)
	lis	%r3, wb_corr_adc@ha
	lhz	%r3, wb_corr_adc@l(%r3)

	# Byte AB = (0.68 + ADC/1023*0.68) * 65536/2
	mulli	%r5, %r3, 22304 # 22304 = ((1 << 25) * 0.68 / 1023
	srwi	%r5, %r5, 10
	addi	%r5, %r5, 22282 # 22282 = ((1 << 15) * 0.68
	sth	%r5, 1(%r4)

	# Byte CD
	# CD = ADC/1023*5*65536/8 = ADC * 40.04
	mulli	%r5, %r3, 20500 # 20500 = ((1 << 25) * 40.04
	srwi	%r5, %r5, 9
	sth	%r5, 3(%r4)

	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef ACCUSUMP
	.set OILPRESSURE, 1
.endif
.ifdef OBDOIL
	.set OILPRESSURE, 1
.endif

hook_OBD_mode_0x22:
	# %r31 is index in obd_resp
	# %r8 is the mode 0x22 pid

	# Store current pointer to response byte in %r4
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r4, %r4, %r31

	# Branching
.ifdef FLEXFUEL
	cmplwi	%r8, 0x0401
	beq	OBD_mode_0x22_pid_0x0401
.endif
.ifdef OILPRESSURE
	cmplwi	%r8, 0x0402
	beq	OBD_mode_0x22_pid_0x0402
.endif
.ifdef WIDEBAND
	cmplwi	%r8, 0x0403
	beq	OBD_mode_0x22_pid_0x0403
.endif
	# Mask %r8 (Erase by patch in original code)
	rlwinm	%r29, %r8, 0,16,31
	ba	hook_OBD_mode_0x22_continue

.ifdef FLEXFUEL
OBD_mode_0x22_pid_0x0401:
	# Fuel temperature
	addi	%r31, %r31, 1 # Answer 1 bytes
	lis	%r3, ethanol_temp@ha
	lbz	%r3, ethanol_temp@l(%r3)
	stb	%r3, 0(%r4)
	ba	hook_OBD_mode_0x22_jump
.endif

.ifdef OILPRESSURE
OBD_mode_0x22_pid_0x0402:
	# Oil Pressure
	addi	%r31, %r31, 2 # Answer 2 bytes
	lis	%r3, oil_pressure@ha
	lha	%r3, oil_pressure@l(%r3)
	sth	%r3, 0(%r4)
	ba	hook_OBD_mode_0x22_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x22_pid_0x0403:
	# Wideband correction slope and offset
	addi	%r31, %r31, 4 # Answer 4 bytes
	lis	%r3, wb_slope@ha
	lhz	%r3, wb_slope@l(%r3)
	sth	%r3, 0(%r4)
	lis	%r3, wb_offset@ha
	lha	%r3, wb_offset@l(%r3)
	sth	%r3, 2(%r4)
	ba	hook_OBD_mode_0x22_jump
.endif
