.section .data

# Calibration size must be a multiple of 4
CAL_extra:
.ascii	"XTRACAL3"
CAL_ethanol_sensor_temp_reactivity:
.byte 0x02
CAL_ethanol_sensor_content_reactivity:
.byte 0x04
CAL_ethanol_sensor_engine_speed_limit:
.byte 0x70 # 4000rpm
CAL_ethanol_sensor_engine_load_limit:
.byte 0xC8 # 800mg/stroke
CAL_extra_end:

.section .bss
.global ethanol_temp, ethanol_content, copy1, copy2, copy3, CAL_base_extra

.lcomm	ethanol_timer,		1
.lcomm	ethanol_temp_avg,	4
.lcomm	ethanol_temp,		1 # 0 = -40°C, 255 = 120°C
.lcomm	ethanol_content_avg,	4
.lcomm	ethanol_content,	1 # 0 = 0%, 255 = 100%
.lcomm	CAL_base_extra,	(CAL_extra_end-CAL_extra) # Copy in RAM of extra CALibration.

.section .text
.globl _start, hook_init, hook_loop, hook_timer_5ms, hook_OBD_mode_0x01

_start:
hook_init:
	bl	copy_calibration
	bl	flexfuel_init

	# Load 128 (Erase by patch in original code)
	li	%r0, 128
	ba	hook_init_continue

hook_loop:
	bl	flexfuel
	ba	hook_loop_continue

hook_timer_5ms:
	bl	flexfuel_5ms

	# Load 10 (Erase by patch in original code)
	li	%r0, 10
	ba	hook_timer_5ms_continue

hook_OBD_mode_0x01:
	# %r3 is index in obd_req
	# %r4 is index in obd_resp

	# Store current request byte in %r5
	lis	%r5, obd_req@ha
	addi	%r5, %r5, obd_req@l
	lbzx	%r5, %r5, %r3

	# Store pointer to response array in %r6
	# Store current pointer to response byte in %r7
	lis	%r6, obd_resp@ha
	addi	%r6, %r6, obd_resp@l
	add	%r7, %r6, %r4

	# Branching
	cmplwi	%r5, 0x40
	beq	OBD_mode_0x01_pid_0x40
	cmplwi	%r5, 0x46
	beq	OBD_mode_0x01_pid_0x46
	cmplwi	%r5, 0x52
	beq	OBD_mode_0x01_pid_0x52

	# Mask %r3 (Erase by patch in original code)
	rlwinm	%r0, %r3, 0,24,31
	ba	hook_OBD_mode_0x01_continue

OBD_mode_0x01_pid_0x40:
	# Available PID 0x41-0x60
	addi	%r4, %r4, 5 # Answer 5 bytes
	stb	%r5, 0(%r7)

	lis	%r5, 0xFED04000@ha
	addi	%r5, %r5, 0xFED04000@l
	stw	%r5, 1(%r7)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x46:
	# Fuel temperature (reported as ambiant air)
	addi	%r4, %r4, 2 # Answer 2 bytes
	stb	%r5, 0(%r7)

	lis	%r5, ethanol_temp@ha
	lbz	%r5, ethanol_temp@l(%r5)

	# Convert from x*5/8-40 to x-40
	# Maximal oil temp will be 120°C!
	mulli	%r5, %r5, 160
	srawi	%r5, %r5, 8
	addze	%r5, %r5

	stb	%r5, 1(%r7)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x52:
	# Ethanol fuel %
	addi	%r4, %r4, 2 # Answer 2 bytes
	stb	%r5, 0(%r7)

	lis	%r5, ethanol_content@ha
	lbz	%r5, ethanol_content@l(%r5)

	stb	%r5, 1(%r7)

	ba	hook_OBD_mode_0x01_jump

copy_calibration:
	# Copy extra calibration
	lis	%r3, CAL_base_extra@ha
	addi	%r3, %r3, CAL_base_extra@l
	subi	%r3, %r3, 4
	lis	%r4, CAL_extra@ha
	addi	%r4, %r4, CAL_extra@l
	subi	%r4, %r4, 4
	li	%r5, (CAL_extra_end-CAL_extra) / 4
	mtctr	%r5
copy_loop:
	lwzu	%r5, 4(%r4)
	stwu	%r5, 4(%r3)
	bdnz	copy_loop
	blr

flexfuel_init:
	# Configure SIU_PCR184 for primary function (Input RG4)
	#li	%r3, 0x0500
	#lis	%r4, 0xC3F901B0@ha
	#sth	%r3, 0xC3F901B0@l(%r4)

	# Configure EMIOS_MCR with 0x34004F00
	#lis	%r3, 0x34004F00@ha
	#addi	%r3, %r3, 0x34004F00@l
	#lis	%r4, 0xC3FA0000@ha
	#stw	%r3, 0xC3FA0000@l(%r4)

	# Prescaler of EMIOS_MCR: 80
	# Prescaler of EMIOS_CCR5: 4
	# Clock: 80000000
	#
	# 80000000 / 80 / 4 = 250000

	# We cannot read the temperature and the content at the same time, so
	# we alternate the measurement.
	#
	#	100 ms reading the temperature
	#	100 ms reading the content
	#
	# The ethanol sensor update his output every 225ms.
	#
	li	%r3, 39
	lis	%r4, ethanol_timer@ha
	stb	%r3, ethanol_timer@l(%r4)

	# Start with 20°C
	li	%r3, 96
	lis	%r4, ethanol_temp@ha
	stb	%r3, ethanol_temp@l(%r4)
	mulli	%r3, %r3, 256
	lis	%r4, ethanol_temp_avg@ha
	stw	%r3, ethanol_temp_avg@l(%r4)

	# Start with 10% ethanol
	li	%r3, 25
	lis	%r4, ethanol_content@ha
	stb	%r3, ethanol_content@l(%r4)
	mulli	%r3, %r3, 256
	lis	%r4, ethanol_content_avg@ha
	stw	%r3, ethanol_content_avg@l(%r4)

	blr

flexfuel:
	# Read EMIOS_CSR5 (Reading Flag)
	lis	%r4, 0xC3FA00D0@ha
	lwz	%r3, 0xC3FA00D0@l(%r4)
	# Mask Flag
	rlwinm	%r5, %r3, 0,31,31
	cmplwi	%r5, 0
	beq	flex_end
	# Reset all flags (by writing 1)
	#lis	%r4, 0xC3FA00D0@ha
	stw	%r3, 0xC3FA00D0@l(%r4)

	# Engine speed limit
	lis	%r5, CAL_base_extra@ha
	addi	%r5, %r5, CAL_base_extra@l
	lbz	%r3, (CAL_ethanol_sensor_engine_speed_limit-CAL_extra)(%r5)
	lis	%r4, engine_speed_3@ha
	lbz	%r4, engine_speed_3@l(%r4)
	cmplw	%r4, %r3
	bge	flex_end

	# Engine load limit
	lis	%r5, CAL_base_extra@ha
	addi	%r5, %r5, CAL_base_extra@l
	lbz	%r3, (CAL_ethanol_sensor_engine_load_limit-CAL_extra)(%r5)
	lis	%r4, load_2@ha
	lbz	%r4, load_2@l(%r4)
	cmplw	%r4, %r3
	bge	flex_end

	# Read EMIOS_CxDR5 (Ethanol temperature or content)
	lis	%r3, 0xC3FA00C0@ha
	lwz	%r4, 0xC3FA00C0@l(%r3) # Data A
	#lis	%r3, 0xC3FA00C4@ha
	lwz	%r5, 0xC3FA00C4@l(%r3) # Data B
	sub	%r3, %r4, %r5 # Data A-B
	# If there is an error (division by 0 or negative number)
	cmpwi	%r3, 0
	ble	flex_end

	# Read the timer
	lis	%r4, ethanol_timer@ha
	lbz	%r4, ethanol_timer@l(%r4)
	cmplwi	%r4, 20
	bge	flex_content

	# Temperature (Duty cycle: 1ms = -40°C and 5ms = 125°C)
	# temp(in °C)   = (((%r3 / 250000 * 1000) - 1ms) * 41.25) - 40
	# temp(5/8-40c) = ((((%r3 / 250000 * 1000) - 1ms) * 41.25) - 40 + 40) * 8 / 5 = (%r3 / 3.787878) - 66 = (%r3 * 33 / 125) - 66
	mulli	%r3, %r3, 33
	li	%r4, 125
	divw	%r3, %r3, %r4
	subi	%r3, %r3, 66
	cmpwi	%r3, 0
	bge	flex_1
	li	%r3, 0 # Minimum is 0
flex_1:
	cmpwi	%r3, 255
	ble	flex_2
	li	%r3, 255 # Maximum is 255
flex_2:
	# Average
	#
	# avg = (avg * (256 - reactivity))/256 + (value * reactivity)
	#
	li	%r4, 256
	lis	%r5, CAL_base_extra@ha
	addi	%r5, %r5, CAL_base_extra@l
	lbz	%r5, (CAL_ethanol_sensor_temp_reactivity-CAL_extra)(%r5)
	sub	%r6, %r4, %r5
	lis	%r7, ethanol_temp_avg@ha
	lwz	%r7, ethanol_temp_avg@l(%r7)
	mullw	%r7, %r7, %r6
	divw	%r7, %r7, %r4
	mullw	%r3, %r3, %r5
	add	%r3, %r3, %r7
	lis	%r7, ethanol_temp_avg@ha
	stw	%r3, ethanol_temp_avg@l(%r7)
	divw	%r3, %r3, %r4
	lis	%r7, ethanol_temp@ha
	stb	%r3, ethanol_temp@l(%r7)
	b	flex_end

flex_content:
	# TODO: If > 160 Hz, water contamination or sensor error.

	# Ethanol Content (Freq: 50Hz = 0% and 150Hz = 100%)
	# percent(in % ) = (250000 / %r3) - 50
	# percent(1/255) = ((250000 / %r3) - 50) / 100 * 255 = (637500 / %r3) - 127
	lis	%r4, 637500@ha
	addi	%r4, %r4, 637500@l
	divw	%r3, %r4, %r3
	subi	%r3, %r3, 127
	cmpwi	%r3, 0
	bge	flex_3
	li	%r3, 0 # Minimum is 0
flex_3:
	cmpwi	%r3, 255
	ble	flex_4
	li	%r3, 255 # Maximum is 255
flex_4:
	# Average
	#
	# avg = (avg * (256 - reactivity))/256 + (value * reactivity)
	#
	li	%r4, 256
	lis	%r5, CAL_base_extra@ha
	addi	%r5, %r5, CAL_base_extra@l
	lbz	%r5, (CAL_ethanol_sensor_content_reactivity-CAL_extra)(%r5)
	sub	%r6, %r4, %r5
	lis	%r7, ethanol_content_avg@ha
	lwz	%r7, ethanol_content_avg@l(%r7)
	mullw	%r7, %r7, %r6
	divw	%r7, %r7, %r4
	mullw	%r3, %r3, %r5
	add	%r3, %r3, %r7
	lis	%r7, ethanol_content_avg@ha
	stw	%r3, ethanol_content_avg@l(%r7)
	divw	%r3, %r3, %r4
	lis	%r7, ethanol_content@ha
	stb	%r3, ethanol_content@l(%r7)
flex_end:
	blr

flexfuel_5ms:
	# Increment the timer every 5ms
	lis	%r4, ethanol_timer@ha
	lbz	%r5, ethanol_timer@l(%r4)
	addi	%r5, %r5, 1
	# At 200ms reset the timer
	cmplwi	%r5, 40
	blt	timer_1
	li	%r5, 0
timer_1:
	#lis	%r4, ethanol_timer@ha
	stb	%r5, ethanol_timer@l(%r4)

	# At 0ms configure for temperature
	cmplwi	%r5, 0
	bne	timer_2
	# Configure EMIOS_CCR5 for pulse width measurement (ethanol temperature)
	li	%r3, 0x0E000604@l
	#addis	%r3, %r3, 0x0E000604@ha
	b	timer_3
timer_2:
	# At 100ms configure for content
	cmplwi	%r5, 20
	bne	timer_4
	# Configure EMIOS_CCR5 for period measurement (ethanol content)
	li	%r3, 0x0E000605@l
	#addis	%r3, %r3, 0x0E000605@ha
timer_3:
	# When changing mode, go through mode 0 with no flag generated.
	li	%r5, 0x0100
	lis	%r4, 0xC3FA00CC@ha
	stw	%r5, 0xC3FA00CC@l(%r4)
	# Reset EMIOS_CSR5 Flag
	#li	%r5, 1
	#lis	%r4, 0xC3FA00D0@ha
	#stw	%r5, 0xC3FA00D0@l(%r4)
	# Change to the desired mode
	addis	%r3, %r3, 0x0E000604@ha
	#lis	%r4, 0xC3FA00CC@ha
	stw	%r3, 0xC3FA00CC@l(%r4)
timer_4:
	blr
