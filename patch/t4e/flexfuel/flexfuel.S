.section .bss
.global ethanol_temp, ethanol_content

.lcomm	ethanol_timer,       1, 1
.lcomm	ethanol_temp,        1, 1 # 0 = -40°C, 255 = 120°C
.lcomm	ethanol_content,     1, 1 # 0 = 0%, 255 = 100%
.lcomm	ethanol_temp_avg,    4, 4
.lcomm	ethanol_content_avg, 4, 4

.section .text
.global flexfuel_init, flexfuel, flexfuel_5ms, lookup_2D_uint8_interpolated_withblend, lookup_3D_uint8_interpolated_withblend

flexfuel_init:
	# Configure MMCSMSCR (free running counter)
	li	%r3, 0x0e00
	lis	%r4, 0x306036@ha
	sth	%r3, 0x306036@l(%r4)

	# Configure MMCSMML
	li	%r3, 0x0000
	lis	%r4, 0x306032@ha
	sth	%r3, 0x306032@l(%r4)

	# Prescaler of MMCSMSCR: 256
	# Prescaler of MCPSM: 2
	# Clock: 40000000
	#
	# 40000000 / 2 / 256 = 78125

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
	slwi	%r3, %r3, 8
	lis	%r4, ethanol_temp_avg@ha
	stw	%r3, ethanol_temp_avg@l(%r4)

	# Start with 10% ethanol
	li	%r3, 25
	lis	%r4, ethanol_content@ha
	stb	%r3, ethanol_content@l(%r4)
	slwi	%r3, %r3, 8
	lis	%r4, ethanol_content_avg@ha
	stw	%r3, ethanol_content_avg@l(%r4)

	blr

flexfuel:
	# Read MIRSM1 (Reading Flag)
	lis	%r4, 0x306C40@ha
	lhz	%r3, 0x306C40@l(%r4)
	rlwinm	%r5, %r3, 17,31,31 # Mask MDA31
	cmplwi	%r5, 0
	beq	flex_end
	rlwinm	%r5, %r3, 0,17,31 # Reset Flag
	#lis	%r4, 0x306C40@ha
	sth	%r5, 0x306C40@l(%r4)

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

	# Read MDA31 (Ethanol temperature or content)
	lis	%r3, 0x3060F8@ha
	lwz	%r3, 0x3060F8@l(%r3)
	rlwinm	%r4, %r3, 16,16,31 # Data A
	rlwinm	%r5, %r3, 0,16,31 # Data B
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
	# temp(in °C)   = (((%r3 / 78125 * 1000) - 1ms) * 41.25) - 40
	# temp(1  -40c) = ((((%r3 / 78125 * 1000) - 1ms) * 41.25) - 40 + 40 = (%r3 * 0.528) - 41.25
	# temp(5/8-40c) = ((((%r3 / 78125 * 1000) - 1ms) * 41.25) - 40 + 40) * 8 / 5 = (%r3 * 0.8448) - 66
	mulli	%r3, %r3, 27682 # 27682 = ((1 << 15) * 0.8448)
	srwi	%r3, %r3, 15
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
	# percent(in % ) = (78125 / %r3) - 50
	# percent(1/255) = ((78125 / %r3) - 50) / 100 * 255 = (199218.75 / %r3) - 127.5
	#
	# Working with the period instead of the frequency to avoid the division
	# does not work as follows (Try with 100Hz or 10ms => 50%):
	#
	# Ethanol Content (Period: 20ms = 0% and 6.66ms = 100%)
	# WRONG: percent(in % ) = 100 - ((%r3 / 78125 * 1000) - 6.66) / (20 - 6.66) * 100
	# WRONG: percent(1/255) = 255 - ((%r3 * 0.2448) - 127.5)
	lis	%r4, 199219@ha
	addi	%r4, %r4, 199219@l
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
	# Configure MDA31 for pulse width measurement (ethanol temperature)
	li	%r3, 0x0001
	b	timer_3
timer_2:
	# At 100ms configure for content
	cmplwi	%r5, 20
	bne	timer_4
	# Configure MDA31 for period measurement (ethanol content)
	li	%r3, 0x0002
timer_3:
	# When changing mode, it's imperative to go through the DIS mode.
	li	%r5, 0
	lis	%r4, 0x3060FE@ha
	sth	%r5, 0x3060FE@l(%r4)
	# Reset MDA31 Flag
	#lis	%r4, 0x306C40@ha
	lhz	%r5, 0x306C40@l(%r4)
	rlwinm	%r5, %r5, 0,17,31 # Reset Flag
	#lis	%r4, 0x306C40@ha
	sth	%r5,  0x306C40@l(%r4)
	# Change to the desired mode
	#lis	%r4, 0x3060FE@ha
	sth	%r3, 0x3060FE@l(%r4)
timer_4:
	blr

# Params:
#	r3 : value for ethanol
#	r4 : value for gasoline
#	r5 : ethanol scale low (E0 = 0, E5 = 12 or E10 = 25)
#	r6 : ethanol scale high (E40 = 102, E85 = 216 or E100 = 255)
#
#	scale_high -= scale_low
#	ethanol_content -= scale_low
#	result = (%r3 * ethanol_content + %r4 * (scale_high - ethanol_content)) / scale_high
fuelblend:
	lis	%r7, ethanol_content@ha
	lbz	%r7, ethanol_content@l(%r7)
	cmplw	%r7, %r5
	ble	only_gas
	cmplw	%r7, %r6
	bge	only_eth
	sub	%r6, %r6, %r5
	sub	%r7, %r7, %r5
	sub	%r8, %r6, %r7
	mullw	%r3, %r3, %r7
	mullw	%r4, %r4, %r8
	add	%r3, %r3, %r4
	divw	%r3, %r3, %r6
only_eth:
	blr
only_gas:
	mr	%r3, %r4
	blr

# Params:
#	r3 : size_x
#	r4 : input_x
#	r5 : lut
#	r6 : x_axis
#
#	r7: lut ethanol
#	r8: ethanol scale low
#	r9: ethanol scale high
lookup_2D_uint8_interpolated_withblend:
	# Push link register on stack (4 bytes alignment, normally 16)
	stwu	%r1, -24(%r1)
	mflr	%r0
	stw	%r0, 28(%r1)

	# Save arguments on stack
	stb	%r3 ,  8(%r1)
	stb	%r4 ,  9(%r1)
	stw	%r7 , 10(%r1)
	stw	%r6 , 14(%r1)
	stb	%r8 , 19(%r1)
	stb	%r9 , 20(%r1)

	# 1st call and save result on stack
	bla	lookup_2D_uint8_interpolated
	stb	%r3,  18(%r1)

	# 2nd call with ethanol table
	lbz	%r3,  8(%r1)
	lbz	%r4,  9(%r1)
	lwz	%r5, 10(%r1)
	lwz	%r6, 14(%r1)
	bla	lookup_2D_uint8_interpolated

	# Both result are in %r3 and %r4
	lbz	%r4, 18(%r1)
	lbz	%r5, 19(%r1)
	lbz	%r6, 20(%r1)
	bl	fuelblend

	# Pop link register from stack
	lwz	%r0, 28(%r1)
	mtlr	%r0
	addi	%r1, %r1, 24
	blr

# Params:
#	r3 : size_x
#	r4 : size_y
#	r5 : input_x
#	r6 : input_y
#	r7 : lut
#	r8 : x_axis
#	r9 : y_axis
#
#	r10: lut ethanol
#	r11: ethanol scale low
#	r12: ethanol scale high
lookup_3D_uint8_interpolated_withblend:
	# Push link register on stack (4 bytes alignment, normally 16)
	stwu	%r1, -28(%r1)
	mflr	%r0
	stw	%r0, 32(%r1)

	# Save arguments on stack
	stb	%r3 ,  8(%r1)
	stb	%r4 ,  9(%r1)
	stb	%r5 , 10(%r1)
	stb	%r6 , 11(%r1)
	stw	%r10, 12(%r1)
	stw	%r8 , 16(%r1)
	stw	%r9 , 20(%r1)
	stb	%r11, 25(%r1)
	stb	%r12, 26(%r1)

	# 1st call and save result on stack
	bla	lookup_3D_uint8_interpolated
	stb	%r3,  24(%r1)

	# 2nd call with ethanol table
	lbz	%r3,  8(%r1)
	lbz	%r4,  9(%r1)
	lbz	%r5, 10(%r1)
	lbz	%r6, 11(%r1)
	lwz	%r7, 12(%r1)
	lwz	%r8, 16(%r1)
	lwz	%r9, 20(%r1)
	bla	lookup_3D_uint8_interpolated

	# Both result are in %r3 and %r4
	lbz	%r4, 24(%r1)
	lbz	%r5, 25(%r1)
	lbz	%r6, 26(%r1)
	bl	fuelblend

	# Pop link register from stack
	lwz	%r0, 32(%r1)
	mtlr	%r0
	addi	%r1, %r1, 28
	blr
