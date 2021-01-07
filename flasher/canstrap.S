.section .text
.globl _start

_start:
	/* Some constant register to minimize code footprint */
	li	%r31, 0x00
	lis	%r30, 0x30
	li	%r29, 0x556C
	lis	%r28, 0xAA39@ha
	addi	%r28, 0, 0xAA39@l

	/* Disable interrupt */
	stw	%r31, -0x3FEC(30) # 0x2FC014 SIMASK1
	stw	%r31, -0x3FB8(30) # 0x2FC048 SIMASK2
	stw	%r31, -0x3FB4(30) # 0x2FC04C SIMASK3

	# CAN-Bus Message
	#
	# PID:        0x60
	# RETURN PID: 0x7A0
	#
	# Echo - Payload will be sended back (and stop countdown)
	#   DATA  : 00 XX XX XX XX XX XX XX
	#   RETURN: 00 XX XX XX XX XX XX XX
	#
	# Read Word - Read 4 Bytes
	#   DATA  : 01 AA AA AA
	#   RETURN: 01 DD DD DD DD
	#
	# Write Word - Write 4 Bytes
	#   DATA  : 02 AA AA AA DD DD DD DD
	#   RETURN: 02
	#
	# Branch:
	#   DATA  : 03 AA AA AA [PP PP PP PP] (PP => Function parameter)
	#   RETURN: N/A
	#
	# Plugin (Branch in main loop):
	#   DATA  : 04 AA AA AA
	#   RETURN: 04

	/* TouCAN A Soft-Reset */
	lhz	%r0, 0x7080(30) # 0x307080 CANMCR_A
	ori	%r0, %r0, 0x0200 # Set bit SOFTRST
	sth	%r0, 0x7080(30)
wait_reset:
	lhz	%r0, 0x7080(30)
	rlwinm	%r0, %r0, 0,22,22 # Mask on bit SOFTRST
	cmplwi	%r0, 0
	bne	wait_reset

	/* TouCAN A Configure */
	/* 28 MHz / (PSEG1+1+PSEG2+1) / (PRESDIV+1) = 1 Mbit/s */
	stb	%r31, 0x7086(30) # 0x307086 CANCTRL0_A

	li	%r0, 0x04 # PROPSEG = 4
	stb	%r0, 0x7087(30) # 0x307087 CANCTRL1_A

	li	%r0, 0xF6 # RJW = 3, PSEG1 = 6, PSEG2 = 6
	stb	%r0, 0x7089(30) # 0x307089 CANCTRL2_A

	li	%r0, 1
	stb	%r0, 0x7088(30) # 0x307088 PRESDIV_A

	/* TouCAN A Disable all buffers */
	li	%r0, 0
loop_disable:
	add	%r3, 30, 0
	sth	%r31, 0x7100(3) # 0x3071x0 MBBUFFx_A
	addi	%r0, 0, 0x10
	cmplwi	%r0, 0xF0
	ble	loop_disable

	/* TouCAN A Configure receive mask for buffer 0-13 */
	lis	%r0, 0xFFE0 # Reception Mask 0x7FF << 21
	stw	%r0, 0x7090(30) # 0x307090 RxGMSK_A

	/* TouCAN A Configure RX Buffer 0 */
	li	%r0, 0xC00 # Reception address 0x60 << 5
	sth	%r0, 0x7102(30) # 0x307102 MBBUFF0_A - ID_HIGH

	li	%r0, 0x40 # Buffer activated and free
	sth	%r0, 0x7100(30) # 0x307100 MBBUFF0_A

	/* TouCAN A Start */
	lhz	%r0, 0x7080(30) # 0x307080 CANMCR_A
	rlwinm	%r0, %r0, 0,20,18 # Clear bit HALT
	sth	%r0, 0x7080(30)

	/* TouCAN A Send "HiCsV1" */
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x71D0(30) # 0x3071D0 MBBUFF13_A

	lis	%r0, 0xF400@ha # Destination address 0x7A0 << 5
	addi	%r0, 0, 0xF400@l
	sth	%r0, 0x71D2(30) # 0x3071D2 MBBUFF13_A - ID_HIGH

	li	%r0, 0x4869 # Data: "Hi" -> Hello
	sth	%r0, 0x71D6(30)

	li	%r0, 0x466C # Data: "Bs" -> Canstrap
	sth	%r0, 0x71D8(30)

	li	%r0, 0x5631 # Data: "V1" -> Version 1
	sth	%r0, 0x71DA(30)

	li	%r0, 0xE6 # Buffer ready + DLC = 6
	sth	%r0, 0x71D0(30)

	/* No plugin */
	li	%r27, -1

	/* Count down from 0x40000 then boot stage II */
	lis	%r26, 0x4 # Approx. 500ms
	li	%r25, -1 # Decrement
loop_main:
	add	%r26, 26, 25
	cmplwi	%r26, 0x0
	beqa	0x004000 # Stage II

	/* Retrigger Watchdog */
	sth	%r29, -0x3FF2(30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(30) # 0x2FC00E SWSR

	/* Data in RX Buffer 0 ? */
	lhz	%r0, 0x70A4(30) # 0x3070A4 IFLAG
	rlwinm	%r0, 0, 0,31,31 # Mask Buffer 0 (Buffer 0 @ LSB)
	cmplwi	%r0, 0x0
	beq	loop_main # Bit not set -> no data

	/* Read Buffer Status (Lock buffer) */
wait_busy:
	lhz	%r0, 0x7100(30) # 0x307100 MBBUFF0_A Control/Status
	rlwinm	%r3, 0, 0,27,27 # Mask on bit BUSY
	cmplwi	%r3, 0x0
	bne	wait_busy

	/* DLC in %r13 */
	rlwinm	%r13, 0, 0,28,31 # Mask Length

	/* Byte 0-3 in %r14 */
	lwz	%r14, 0x7106(30)

	/* Byte 4-7 in %r15 */
	lwz	%r15, 0x710A(30)

	/* Clear RX buffer */
	li	%r0, 0x40 # Buffer activated and free
	sth	%r0, 0x7100(30) # 0x307100 MBBUFF0_A
	lhz	%r0, 0x7104(30) # 0x307104 MBBUFF0_A - Timestamp (Unlock buffer)
	sth	%r31, 0x70A4(30) # 0x3070A4 IFLAG

	/* DLC == 0 break */
	cmplwi	%r13, 0
	beq	loop_main # DLC is 0

	/* Command in %r16 */
	rlwinm	%r16, 14, 8,24,31 # r16 = (r14 >> 24) & 0xFF

	/* Address in %r17 */
	rlwinm	%r17, 14, 0,8,31 # r17 = r14 & 0xFFFFFF

	/* Lock TX Buffer 13 */
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x71D0(30) # 0x3071D0 TouCAN A Buffer 13

	/* Echo command 0x00 */
	cmplwi	%r16, 0x00
	bne	end_command_0x00
	/* Answer */
	stw	%r14, 0x71D6(30)
	stw	%r15, 0x71DA(30)
	ori	%r0, 13, 0xE0 # Buffer ready + Copy DLC
	sth	%r0, 0x71D0(30)
	/* Stop the countdown */
	li	%r25, 0
	b	loop_main
end_command_0x00:

	/* Read command 0x01 */
	cmplwi	%r16, 0x01
	bne	end_command_0x01
	cmplwi	%r13, 4
	bne	loop_main # DLC is not 4
	lwz	%r0, 0(17) # Read
	/* Answer */
	stb	%r16, 0x71D6(30)
	stw	%r0, 0x71D7(30)
	li	%r0, 0xE5 # Buffer ready + DLC = 5
	sth	%r0, 0x71D0(30)
	b	loop_main
end_command_0x01:

	/* Write command 0x02 */
	cmplwi	%r16, 0x02
	bne	end_command_0x02
	cmplwi	%r13, 8
	bne	loop_main # DLC is not 8
	stw	%r15, 0(17) # Write
	bl	sub_answer1
	b	loop_main
end_command_0x02:

	/* Branch command 0x03 */
	cmplwi	%r16, 0x03
	bne	end_command_0x03
	cmplwi	%r13, 4
	blt	loop_main # DLC is < 4
	mtctr	%r17
	bctrl	# Optional parameter in %r15
end_command_0x03:

	/* Plugin command 0x04 */
	cmplwi	%r16, 0x04
	bne	end_command_0x04
	cmplwi	%r13, 4
	bne	loop_main # DLC is not 4
	mr	%r27, %r17
	bl	sub_answer1
end_command_0x04:

	/* Run plugin */
	cmplwi	%r27, -1
	beq	loop_main # No plugin
	mtctr	%r27
	bctrl
	b	loop_main

sub_answer1:
	/* Answer just with the command byte */
	stb	%r16, 0x71D6(30)
	li	%r0, 0xE1 # Buffer ready + DLC = 1
	sth	%r0, 0x71D0(30)
	blr

