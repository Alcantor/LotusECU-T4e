# Mode 1 PID Mask
.set OBD_PID_0x00_MASK, 0xFFFFB993
.set OBD_PID_0x20_MASK, 0x8007E001
.set OBD_PID_0x40_MASK, 0xFED08001
.set OBD_PID_0x60_MASK, 0x00000200

.section .text
.global hook_OBD_mode_0x01, hook_OBD_mode_0x22

hook_OBD_mode_0x01:
	# %r31 is index in obd_req
	# %r30 is index in obd_resp

	# Store current request byte in %r3
	lis	%r3, obd_req@ha
	addi	%r3, %r3, obd_req@l
	lbzx	%r3, %r3, %r31

	# Store current pointer to response byte in %r4
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r4, %r4, %r30

	# Branching
	cmplwi	%r3, 0x00
	#beq	OBD_mode_0x01_pid_0x00
	#cmplwi	%r3, 0x20
	beq	OBD_mode_0x01_pid_0x20
	cmplwi	%r3, 0x40
	beq	OBD_mode_0x01_pid_0x40
.ifdef FLEXFUEL
.set OBD_PID_0x40_MASK, OBD_PID_0x40_MASK | 1<<(0x60-0x52)
	cmplwi	%r3, 0x52
	beq	OBD_mode_0x01_pid_0x52
.endif
.ifdef WIDEBAND
.set OBD_PID_0x20_MASK, OBD_PID_0x20_MASK | 1<<(0x40-0x24)
	cmplwi	%r3, 0x24
	beq	OBD_mode_0x01_pid_0x24
.set OBD_PID_0x20_MASK, OBD_PID_0x20_MASK | 1<<(0x40-0x25)
	cmplwi	%r3, 0x25
	beq	OBD_mode_0x01_pid_0x25
.endif
	# Mask %r31 (Erase by patch in original code)
	rlwinm	%r0, %r31, 0,24,31
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
	addi	%r30, %r30, 5 # Answer 5 bytes
	stb	%r3, 0(%r4)
	stw	%r5, 1(%r4)
	ba	hook_OBD_mode_0x01_jump

.ifdef FLEXFUEL
OBD_mode_0x01_pid_0x52:
	# Ethanol fuel %
	addi	%r30, %r30, 2 # Answer 2 bytes
	stb	%r3, 0(%r4)

	lis	%r3, ethanol_content@ha
	lbz	%r3, ethanol_content@l(%r3)

	stb	%r3, 1(%r4)

	ba	hook_OBD_mode_0x01_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x01_pid_0x24:
	lis	%r6, wb_bank1@ha
	addi	%r6, %r6, wb_bank1@l
	ba	OBD_mode_0x01_pid_0x24_0x25

OBD_mode_0x01_pid_0x25:
	lis	%r6, wb_bank2@ha
	addi	%r6, %r6, wb_bank2@l
	ba	OBD_mode_0x01_pid_0x24_0x25

OBD_mode_0x01_pid_0x24_0x25:
	# Wideband Lambda
	addi	%r30, %r30, 5 # Answer 5 bytes
	stb	%r3, 0(%r4)

	# Corrected Pre-O2 WB input (0V = 10 AFR, 5V = 20 AFR)
	lhz	%r6, wb_corr_adc(%r6)

	# Byte AB = (0.68 + ADC/1023*0.68) * 65536/2
	mulli	%r5, %r6, 22304 # 22304 = ((1 << 25) * 0.68 / 1023
	srwi	%r5, %r5, 10
	addi	%r5, %r5, 22282 # 22282 = ((1 << 15) * 0.68
	sth	%r5, 1(%r4)

	# Byte CD
	# CD = ADC/1023*5*65536/8 = ADC * 40.04
	mulli	%r5, %r6, 20500 # 20500 = ((1 << 25) * 40.04
	srwi	%r5, %r5, 9
	sth	%r5, 3(%r4)

	ba	hook_OBD_mode_0x01_jump
.endif

hook_OBD_mode_0x22:
	# %r3 is index in obd_resp
	# %r0 is the mode 0x22 pid

	# Store current pointer to response byte in %r4
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r4, %r4, %r3

	# Branching
.ifdef FLEXFUEL
	cmplwi	%r0, 0x0401
	beq	OBD_mode_0x22_pid_0x0401
.endif
.ifdef WIDEBAND
	cmplwi	%r0, 0x0403
	beq	OBD_mode_0x22_pid_0x0403
	cmplwi	%r0, 0x0404
	beq	OBD_mode_0x22_pid_0x0404
.endif
	# Mask %r0 (Erase by patch in original code)
	rlwinm	%r4, %r0, 0,16,31
	ba	hook_OBD_mode_0x22_continue

.ifdef FLEXFUEL
OBD_mode_0x22_pid_0x0401:
	# Fuel temperature
	addi	%r3, %r3, 1 # Answer 1 bytes
	lis	%r5, ethanol_temp@ha
	lbz	%r5, ethanol_temp@l(%r5)
	stb	%r5, 0(%r4)
	ba	hook_OBD_mode_0x22_jump
.endif

.ifdef WIDEBAND
OBD_mode_0x22_pid_0x0403:
	# Wideband correction slope and offset bank1
	addi	%r3, %r3, 4 # Answer 4 bytes
	lis	%r5, wb_bank1@ha
	addi	%r5, %r5, wb_bank1@l
	lhz	%r6, wb_slope(%r5)
	sth	%r6, 0(%r4)
	lha	%r6, wb_offset(%r5)
	sth	%r6, 2(%r4)
	ba	hook_OBD_mode_0x22_jump

OBD_mode_0x22_pid_0x0404:
	# Wideband correction slope and offset bank2
	addi	%r3, %r3, 4 # Answer 4 bytes
	lis	%r5, wb_bank2@ha
	addi	%r5, %r5, wb_bank2@l
	lhz	%r6, wb_slope(%r5)
	sth	%r6, 0(%r4)
	lha	%r6, wb_offset(%r5)
	sth	%r6, 2(%r4)
	ba	hook_OBD_mode_0x22_jump
.endif
