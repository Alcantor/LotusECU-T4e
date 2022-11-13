.section .text
.globl _start

_start:
	/* Some constant register to minimize code footprint */
	li	%r31, 0x00
	lis	%r30, 0x30
	li	%r29, 0x556C
	lis	%r28, 0xAA39@ha
	addi	%r28, %r28, 0xAA39@l

	/* Disable interrupt */
	stw	%r31, -0x3FEC(%r30) # 0x2FC014 SIMASK1
	stw	%r31, -0x3FB8(%r30) # 0x2FC048 SIMASK2
	stw	%r31, -0x3FB4(%r30) # 0x2FC04C SIMASK3

	/* Set PPL */
	/* This is already done by bootloader stage I, but not by BDM */
	/* 4 MHz XTAL * (MF+1) = 40 MHz */
	lis	%r0, 0x0090 # MF = 9
	stw	%r0, -0x3D7C(%r30) # 0x2FC284 PLPRCR
wait_ppl:
	lwz	%r0, -0x3D7C(%r30)
	rlwinm	%r0, %r0, 0,15,15 # Mask on bit SPLS
	cmplwi	%r0, 0
	beq	wait_ppl

	/* IMB3 frequency is the same as that of the U-bus */
	stw	%r31, 0x7F80(%r30) # 0x307F80 UMCR

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
	lhz	%r0, 0x7080(%r30) # 0x307080 CANMCR_A
	ori	%r0, %r0, 0x0200 # Set bit SOFTRST
	sth	%r0, 0x7080(%r30)
wait_reset:
	lhz	%r0, 0x7080(%r30)
	rlwinm	%r0, %r0, 0,22,22 # Mask on bit SOFTRST
	cmplwi	%r0, 0
	bne	wait_reset

	/* TouCAN A Configure */
	/* 40 MHz / (1+PROPSEG+1+PSEG1+1+PSEG2+1) / (PRESDIV+1) = 1 Mbit/s */
	lis	%r3, 0x0004 # PROPSEG = 4
	addi	%r0, %r3, 0x01F6 # PRESDIV = 1, RJW = 3, PSEG1 = 6, PSEG2 = 6 - White Version (1 Mbit/s)
#	addi	%r0, %r3, 0x03F6 # PRESDIV = 3, RJW = 3, PSEG1 = 6, PSEG2 = 6 - Black Version (500 kbit/s)
	stw	%r0, 0x7086(%r30) # 0x307086 CANCTRL0_A + CANCTRL1_A + PRESDIV_A + CANCTRL2_A

	/* TouCAN A Disable all buffers */
	li	%r3, 0
loop_disable:
	add	%r4, %r30, %r3
	sth	%r31, 0x7100(%r4) # 0x3071x0 MBBUFFx_A
	addi	%r3, %r3, 0x10
	cmplwi	%r3, 0xF0
	ble	loop_disable

	/* TouCAN A Configure receive mask for buffer 0-13 */
	lis	%r0, 0xFFE0 # Reception Mask 0x7FF << 21
	stw	%r0, 0x7090(%r30) # 0x307090 RxGMSK_A

	/* TouCAN A Configure RX Buffer 0 */
	lis	%r3, 0x40 # Buffer activated and free
	addi	%r0, %r3, 0xC00 # Reception address 0x60 << 5
	stw	%r0, 0x7100(%r30) # 0x307100 MBBUFF0_A

	/* TouCAN A Start */
	lhz	%r0, 0x7080(%r30) # 0x307080 CANMCR_A
	rlwinm	%r0, %r0, 0,20,18 # Clear bit HALT
	sth	%r0, 0x7080(%r30)

	/* No plugin */
	li	%r27, -1

	/* Count down from 0x40000 then boot stage II */
	lis	%r26, 0x4 # Approx. 500ms
	li	%r25, -1 # Decrement

	/* Send "HiCsV1" */
	li	%r24, 6 # Answer 6 bytes
	lis	%r23, 0x48694373@ha # Data: "HiCs" -> Hello Canstrap
	addi	%r23, %r23, 0x48694373@l
	lis	%r22, 0x5631 # Data: "V1" -> Version 1
	#b	answer

answer:
	/* Answer (echo if no modification to %r24, %r23, %r22) */
	lis	%r3, 0x80F400@ha # Buffer not ready + DLC = 0 + Address = 0x7A0 << 5
	addi	%r0, %r3, 0x80F400@l
	stw	%r0, 0x71D0(%r30) # 0x3071D0 MBBUFF13_A
	stw	%r23, 0x71D6(%r30)
	stw	%r22, 0x71DA(%r30)
	ori	%r0, %r24, 0xE0 # Buffer ready + DLC
	sth	%r0, 0x71D0(%r30)
	#b	loop_main

loop_main:
	/* Count down */
	add	%r26, %r26, %r25
	cmplwi	%r26, 0x0
	beqa	0x004000 # Stage II - White Version
#	beqa	0x001FDC # Bootloader - Black Version

	/* Retrigger Watchdog */
	sth	%r29, -0x3FF2(%r30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(%r30) # 0x2FC00E SWSR

	/* Data in RX Buffer 0 ? */
	lhz	%r0, 0x70A4(%r30) # 0x3070A4 IFLAG
	rlwinm	%r0, %r0, 0,31,31 # Mask Buffer 0 (Buffer 0 @ LSB)
	cmplwi	%r0, 0x0
	beq	loop_main # Bit not set -> no data

	/* Read Buffer Status (Lock buffer) */
wait_busy:
	lhz	%r0, 0x7100(%r30) # 0x307100 MBBUFF0_A Control/Status
	rlwinm	%r3, %r0, 0,27,27 # Mask on bit BUSY
	cmplwi	%r3, 0x0
	bne	wait_busy

	/* DLC in %r24 */
	rlwinm	%r24, %r0, 0,28,31 # Mask Length

	/* Bytes 0-3 in %r23 */
	lwz	%r23, 0x7106(%r30)

	/* Bytes 4-7 in %r22 */
	lwz	%r22, 0x710A(%r30)

	/* Clear RX buffer */
	li	%r0, 0x40 # Buffer activated and free
	sth	%r0, 0x7100(%r30) # 0x307100 MBBUFF0_A
	lhz	%r0, 0x7104(%r30) # 0x307104 MBBUFF0_A - Timestamp (Unlock buffer)
	sth	%r31, 0x70A4(%r30) # 0x3070A4 IFLAG

	/* DLC == 0 break */
	cmplwi	%r24, 0
	beq	loop_main # DLC is 0

	/* Command in %r21 */
	rlwinm	%r21, %r23, 8,24,31 # r21 = (r23 >> 24) & 0xFF

	/* Address in %r20 */
	rlwinm	%r20, %r23, 0,8,31 # r20 = r23 & 0xFFFFFF

	/* Echo command 0x00 */
	cmplwi	%r21, 0x00
	bne	end_command_0x00
	/* Stop the countdown */
	li	%r25, 0
	b	answer
end_command_0x00:

	/* Read command 0x01 */
	cmplwi	%r21, 0x01
	bne	end_command_0x01
	cmplwi	%r24, 4
	bne	loop_main # DLC is not 4
	li	%r24, 5 # Answer 5 bytes
	lwz	%r0, 0(%r20) # Read
	rlwimi	%r23, %r0, 24,8,31 # r23 = (r23 & 0xFF000000) | ((r0 >> 8) & 0x00FFFFFF)
	rlwinm	%r22, %r0, 24,0,7 # r22 = (r0 << 24) & 0xFF000000
	b	answer
end_command_0x01:

	/* Write command 0x02 */
	cmplwi	%r21, 0x02
	bne	end_command_0x02
	cmplwi	%r24, 8
	bne	loop_main # DLC is not 8
	li	%r24, 1 # Answer 1 byte
	stw	%r22, 0(%r20) # Write
	b	answer
end_command_0x02:

	/* Branch command 0x03 */
	cmplwi	%r21, 0x03
	bne	end_command_0x03
	cmplwi	%r24, 4
	blt	loop_main # DLC is < 4
	li	%r24, 0 # Answer 0 byte, except if function overwrite %r24
	mtctr	%r20
	bctrl	# Optional parameter in %r22
	b	answer_check
end_command_0x03:

	/* Plugin command 0x04 */
	cmplwi	%r21, 0x04
	bne	end_command_0x04
	cmplwi	%r24, 4
	bne	loop_main # DLC is not 4
	li	%r24, 1 # Answer 1 byte
	mr	%r27, %r20
	b	answer
end_command_0x04:

	/* Run plugin */
	cmplwi	%r27, -1
	beq	loop_main # No plugin installed
	mtctr	%r27
	bctrl
	#b	answer_check

answer_check:
	/* If DLC is 0, do not answer */
	cmplwi	%r24, 0
	beq	loop_main
	b	answer

