.section .data

CAL_extra:
CAL_ethanol_sensor_reactivity:
.byte 0x04
CAL_padding:
.byte 0xFF, 0xFF, 0xFF
CAL_extra_end:

.section .bss

.lcomm	ethanol_percent_avg,	4
.lcomm	ethanol_percent,	1 # 0 = 0%, 255 = 100%
.lcomm	CAL_base_extra,	(CAL_extra_end-CAL_extra) # Copy in RAM of extra CALibration.

.section .text
.globl _start, hook_init, hook_loop, hook_OBD_mode_0x01

_start:
hook_init:
	# Copy extra calibration
	lis	%r3, CAL_base_extra@ha
	addi	%r3, %r3, CAL_base_extra@l
	subi	%r3, %r3, 4
	lis	%r4, CAL_extra@ha
	addi	%r4, %r4, CAL_extra@l
	subi	%r4, %r4, 4
	li	%r5, (CAL_extra_end-CAL_extra) / 4
	mtctr	%r5
cal_copy:
	lwzu	%r5, 4(%r4)
	stwu	%r5, 4(%r3)
	bdnz	cal_copy

	# Configure MMCSMSCR (free running counter)
	li	%r3, 0x0e00
	lis	%r4, 0x306036@ha
	sth	%r3, 0x306036@l(%r4)

	# Configure MMCSMML
	li	%r3, 0x0000
	lis	%r4, 0x306032@ha
	sth	%r3, 0x306032@l(%r4)

	# Configure MDA31 for period measurement
	li	%r3, 0x0002
	lis	%r4, 0x3060FE@ha
	sth	%r3, 0x3060FE@l(%r4)

	# Prescaler of MMCSMSCR: 256
	# Prescaler of MCPSM: 2
	# Clock: 40000000
	#
	# 40000000 / 2 / 256 = 78125

	# Start with a default of 70% ethanol (70*255/100)
	li	%r3, 178
	lis	%r4, ethanol_percent@ha
	stb	%r3, ethanol_percent@l(%r4)
	mulli	%r3, %r3, 2560
	lis	%r4, ethanol_percent_avg@ha
	stw	%r3, ethanol_percent_avg@l(%r4)

	blr

hook_loop:
	bl	flexfuel
	ba	hook_loop_continue

hook_OBD_mode_0x01:
	# %r30 is index in obd_req
	# %r31 is index in obd_resp

	# Store current request byte in %r3
	lis	%r3, obd_req@ha
	addi	%r3, %r3, obd_req@l
	add	%r3, %r3, %r30
	lbz	%r3, 0(%r3)

	# Store pointer to response array in %r4
	# Store current pointer to response byte in %r5
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r5, %r4, %r31

	# Branching
	cmplwi	%r3, 0x40
	beq	OBD_mode_0x01_pid_0x40
	cmplwi	%r3, 0x52
	beq	OBD_mode_0x01_pid_0x52

	# Mask %r30 (Erase by patch in original code)
	rlwinm	%r0, %r30, 0,24,31
	ba	hook_OBD_mode_0x01_continue

OBD_mode_0x01_pid_0x40:
	# Available PID 0x41-0x60
	addi	%r31, %r31, 1
	stb	%r3, 0(%r5)

	lis	%r3, 0x6AC04000@ha
	addi	%r3, %r3, 0x6AC04000@l
	add	%r5, %r4, %r31
	addi	%r31, %r31, 4
	stw	%r3, 0(%r5)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x52:
	# Ethanol fuel %
	addi	%r31, %r31, 1
	stb	%r3, 0(%r5)

	lis	%r3, ethanol_percent@ha
	lbz	%r3, ethanol_percent@l(%r3)

	add	%r5, %r4, %r31
	addi	%r31, %r31, 1
	stb	%r3, 0(%r5)

	ba	hook_OBD_mode_0x01_jump

flexfuel:
	# Read MDA31 (Ethanol percent)
	lis	%r3, 0x3060F8@ha
	lwz	%r3, 0x3060F8@l(%r3)
	rlwinm	%r4, %r3, 16,16,31 # Data A
	rlwinm	%r5, %r3, 0,16,31 # Data B
	sub	%r3, %r4, %r5 # Data A-B
	rlwinm	%r3, %r3, 0,16,31 # Mask 0xFFFF
	# If there is an error (division by 0)
	cmpwi	%r3, 0
	beq	eth_error
	# Convert period into freq then into percent (0 to 255)
	# 78125 * 255 / 100 = 199219
	lis	%r4, 199219@ha
	addi	%r4, %r4, 199219@l
	divw	%r3, %r4, %r3
	subi	%r3, %r3, 128
	cmpwi	%r3, 0
	bge	eth_ge0
	li	%r3, 0 # Minimum is 0
eth_ge0:
	cmpwi	%r3, 255
	ble	eth_le255
	li	%r3, 255 # Maximum is 255
eth_le255:
	# Average
	#
	# avg = (avg * (2560 - reactivity))/2560 + (value * reactivity)
	#
	li	%r4, 2560
	lis	%r5, CAL_base_extra@ha
	addi	%r5, %r5, CAL_base_extra@l
	lbz	%r5, (CAL_ethanol_sensor_reactivity-CAL_extra)(%r5)
	sub	%r6, %r4, %r5
	lis	%r7, ethanol_percent_avg@ha
	lwz	%r7, ethanol_percent_avg@l(%r7)
	mullw	%r7, %r7, %r6
	divw	%r7, %r7, %r4
	mullw	%r3, %r3, %r5
	add	%r3, %r3, %r7
	lis	%r7, ethanol_percent_avg@ha
	stw	%r3, ethanol_percent_avg@l(%r7)
	divw	%r3, %r3, %r4
	lis	%r7, ethanol_percent@ha
	stb	%r3, ethanol_percent@l(%r7)
eth_error:
	blr
