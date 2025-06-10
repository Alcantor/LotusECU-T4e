.section .bss
.global ethanol_temp, ethanol_content

.lcomm	ethanol_timer,       1, 1
.lcomm	ethanol_temp_avg,    4, 4
.lcomm	ethanol_temp,        1, 1 # 0 = -40°C, 255 = 120°C
.lcomm	ethanol_content_avg, 4, 4
.lcomm	ethanol_content,     1, 1 # 0 = 0%, 255 = 100%

.section .text
.global flexfuel_init, flexfuel, flexfuel_5ms

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

	# Load CAL_base_extra into r12 for multiple uses
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l

	# Engine speed limit
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r3, OFF_CAL_ethanol_sensor_engine_speed_limit(%r12)
	lis	%r4, engine_speed_3@ha
	lbz	%r4, engine_speed_3@l(%r4)
	cmplw	%r4, %r3
	bge	flex_end

	# Engine load limit
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r3, OFF_CAL_ethanol_sensor_engine_load_limit(%r12)
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
	# temp(5/8-40c) = ((((%r3 / 250000 * 1000) - 1ms) * 41.25) - 40 + 40) * 8 / 5 = (%r3 * 0.264) - 66
	mulli	%r3, %r3, 17302 # 17302 = ((1 << 16) * 0.264)
	srwi	%r3, %r3, 16
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
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_ethanol_sensor_temp_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, ethanol_temp_avg@ha
	lwz	%r6, ethanol_temp_avg@l(%r7)
	mullw	%r6, %r6, %r5
	srwi	%r6, %r6, 8
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, ethanol_temp_avg@ha
	stw	%r3, ethanol_temp_avg@l(%r7)
	srwi	%r3, %r3, 8
	lis	%r4, ethanol_temp@ha
	stb	%r3, ethanol_temp@l(%r4)
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
	#lis	%r12, CAL_base_extra@ha
	#addi	%r12, %r12, CAL_base_extra@l
	lbz	%r4, OFF_CAL_ethanol_sensor_content_reactivity(%r12)
	subfic	%r5, %r4, 256
	lis	%r7, ethanol_content_avg@ha
	lwz	%r6, ethanol_content_avg@l(%r7)
	mullw	%r6, %r6, %r5
	srwi	%r6, %r6, 8
	mullw	%r3, %r3, %r4
	add	%r3, %r3, %r6
	#lis	%r7, ethanol_content_avg@ha
	stw	%r3, ethanol_content_avg@l(%r7)
	srwi	%r3, %r3, 8
	lis	%r4, ethanol_content@ha
	stb	%r3, ethanol_content@l(%r4)
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
