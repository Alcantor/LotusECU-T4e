.section .text
.globl _start

_start:
	/* Always 0x30 in r3 to minimize code footprint */
	lis	%r3, 0x30

	/* Disable interrupt */
	li	%r0, 0
	stw	%r0, -0x3FEC(3) # 0x2FC014 SIMASK1
	stw	%r0, -0x3FB8(3) # 0x2FC048 SIMASK2
	stw	%r0, -0x3FB4(3) # 0x2FC04C SIMASK3

	# CAN-Bus Message for Flasher
	#
	# PID:        0x60
	# RETURN PID: 0x7A0
	#
	# Echo - Payload will be sended back
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
	# Erase Block
	#   DATA  : 03 MM (MM => Blocks Mask)
	#   RETURN: 03 0G (G => PEGOOD)
	#
	# Start Block Programming
	#   DATA  : 04 MM (MM => Blocks Mask)
	#   RETURN: 04
	#
	# Program Block - Program 4 Bytes
	#   DATA  : 05 AA AA AA DD DD DD DD 
	#   RETURN: 05 0G (G => PEGOOD)
	#
	# Stop Block Programming
	#   DATA  : 06
	#   RETURN: 06
	#
	# Reset:
	#   DATA  : 07
	#   RETURN: N/A

	/* TouCAN A Soft-Reset */
	lhz	%r0, 0x7080(3) # 0x307080 CANMCR_A
	ori	%r0, %r0, 0x200 # Set bit SOFTRST
	sth	%r0, 0x7080(3)
wait_reset:
	lhz	%r0, 0x7080(3)
	rlwinm	%r0, %r0, 0,22,22 # Mask on bit SOFTRST
	cmplwi	%r0, 0
	bne	wait_reset

	/* TouCAN A Configure */
	/* 28 MHz / (PSEG1+1+PSEG2+1) / (PRESDIV+1) = 1 Mbit/s */
	li	%r0, 0x00
	stb	%r0, 0x7086(3) # 0x307086 CANCTRL0_A

	li	%r0, 0x04 # PROPSEG = 4
	stb	%r0, 0x7087(3) # 0x307087 CANCTRL1_A

	li	%r0, 0xF6 # RJW = 3, PSEG1 = 6, PSEG2 = 6
	stb	%r0, 0x7089(3) # 0x307089 CANCTRL2_A

	li	%r0, 1
	stb	%r0, 0x7088(3) # 0x307088 PRESDIV_A

	/* TouCAN A Disable all buffers */
	li	%r0, 0x00 # Buffer disabled
	li	%r4, 0x7100
loop_disable:
	add	%r5, 3, 4 # 0x3071x0 MBBUFFx_A
	sth	%r0, 0(5)
	addi	%r4, 4, 0x10
	cmplwi	%r4, 0xF0
	ble	loop_disable

	/* TouCAN A Configure receive mask for buffer 0-13 */
	lis	%r0, 0xFFE0 # Reception Mask 0x7FF << 21
	stw	%r0, 0x7090(3) # 0x307090 RxGMSK_A

	/* TouCAN A Configure RX Buffer 0 */
	li	%r0, 0xC00 # Reception address 0x60 << 5
	sth	%r0, 0x7102(3) # 0x307102 MBBUFF0_A - ID_HIGH

	li	%r0, 0x40 # Buffer activated and free
	sth	%r0, 0x7100(3) # 0x307100 MBBUFF0_A

	li	%r0, 0x1 # TODO: Is that really needed ? Try 0
	sth	%r0, 0x70A2(3) # 0x3070A2 IMASK

	/* TouCAN A Start */
	lhz	%r0, 0x7080(3) # 0x307080 CANMCR_A
	rlwinm	%r0, %r0, 0,20,18 # Clear bit HALT
	sth	%r0, 0x7080(3)

	/* TouCAN A wait ready */
wait_ready:
	lhz	%r0, 0x7480(3) # 0x307080 CANMCR_A
	rlwinm	%r0, %r0, 0,20,20 # Mask on bit NOTRDY
	cmpwi	%r0, 0
	bne	wait_ready

	/* TouCAN A Send "Hello!" */
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x71D0(3) # 0x3071D0 MBBUFF13_A

	lis	%r0, 0xF400@ha # Destination address 0x7A0 << 5
	addi	%r0, 0, 0xF400@l
	sth	%r0, 0x71D2(3) # 0x3071D2 MBBUFF13_A - ID_HIGH

	li	%r0, 0x4865 # Data: "He"
	sth	%r0, 0x71D6(3)

	li	%r0, 0x6C6C # Data: "ll"
	sth	%r0, 0x71D8(3)

	li	%r0, 0x6F21 # Data: "o!"
	sth	%r0, 0x71DA(3)

	li	%r0, 0xE6 # Buffer ready + DLC = 6
	sth	%r0, 0x71D0(3)
loop_main:
	/* Retrigger Watchdog */
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR
	lis	%r0, 1
	addi	%r0, 0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR

	/* Data in RX Buffer 0 ? */
	lhz	%r0, 0x70A4(3) # 0x3070A4 IFLAG
	rlwinm	%r0, 0, 0,31,31 # Mask Buffer 0 (Buffer 0 @ LSB)
	cmplwi	%r0, 0x0
	beq	loop_main # Bit not set -> no data

	/* Read Buffer Status (Lock buffer) */
wait_busy:
	lhz	%r0, 0x7100(3) # 0x307100 MBBUFF0_A Control/Status
	rlwinm	%r4, 0, 0,27,27 # Mask on bit BUSY
	cmplwi	%r4, 0x0
	bne	wait_busy

	/* DLC in %r4 */
	rlwinm	%r4, 0, 0,28,31 # Mask Length

	/* Byte 0-3 in %r5 */
	lwz	%r5, 0x7106(3)

	/* Byte 4-7 in %r6 */
	lwz	%r6, 0x710A(3)

	/* Clear RX buffer */
	li	%r0, 0x40 # Buffer activated and free
	sth	%r0, 0x7100(3) # 0x307100 MBBUFF0_A
	lhz	%r0, 0x7104(3) # 0x307104 MBBUFF0_A - Timestamp (Unlock buffer)
	li	%r0, 0
	sth	%r0, 0x70A4(3) # 0x3070A4 IFLAG

	/* DLC == 0 break */
	cmplwi	%r4, 0
	beq	loop_main # DLC is 0

	/* Command in %r7 */
	rlwinm	%r7, 5, 8,24,31 # r7 = (r5 >> 24) & 0xFF

	/* Address in %r8 */
	rlwinm	%r8, 5, 0,8,31 # r8 = r5 & 0xFFFFFF

	/* Blocks Mask in %r9 */
	rlwinm	%r9, 5, 16,24,31 # r8 = (r5 >> 16) & 0xFF

	/* Lock TX Buffer 13 */
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x71D0(3) # 0x3071D0 TouCAN A Buffer 13

	/* Echo command 0x00 */
	cmplwi	%r7, 0x00
	bne	end_command_0x00
	stw	%r5, 0x71D6(3)
	stw	%r6, 0x71DA(3)
	ori	%r0, 4, 0xE0 # Buffer ready + Copy DLC
	sth	%r0, 0x71D0(3)
	bl	loop_main
end_command_0x00:

	/* Read command 0x01 */
	cmplwi	%r7, 0x01
	bne	end_command_0x01
	cmplwi	%r4, 4
	bne	loop_main # DLC is not 4
	lwz	%r8, 0(8) # Read
	stb	%r7, 0x71D6(3)
	stw	%r8, 0x71D7(3)
	li	%r0, 0xE5 # Buffer ready + DLC = 5
	sth	%r0, 0x71D0(3)
	bl	loop_main
end_command_0x01:

	/* Write command 0x02 */
	cmplwi	%r7, 0x02
	bne	end_command_0x02
	cmplwi	%r4, 8
	bne	loop_main # DLC is not 8
	stw	%r6, 0(8) # Write
	stb	%r7, 0x71D6(3)
	li	%r0, 0xE1 # Buffer ready + DLC = 1
	sth	%r0, 0x71D0(3)
	bl	loop_main
end_command_0x02:

	/* Erase command 0x03 */
	cmplwi	%r7, 0x03
	bne	end_command_0x03
	cmplwi	%r4, 2
	bne	loop_main # DLC is not 2
	/* Unlock */
	stb	%r9, -0x37F6(3) # 0x2FC80A UC3FCTL - Block
	nand	%r0, 9, 9 # Invert
	stb	%r0, -0x37FD(3) # 0x2FC803 UC3FMCR - Protect
	/* Erase */
	li	%r0, 0x06 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=0
	stb	%r0, -0x37F5(3) # 0x2FC80B UC3FCTL - Bit 24-31
	stw	%r0, 0(0) # Interlock (Dummy write to the flash) # TODO: Should it be in the block?
	li	%r0, 0x07 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=1
	stb	%r0, -0x37F5(3) # 0x2FC80B UC3FCTL - Bit 24-31
wait_hvs:
	/* Erase could be long -> Retrigger Watchdog */
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR
	lis	%r0, 1
	addi	%r0, 0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR
	/* Wait */
	lbz	%r0, -0x37F8(3) # 0x2FC808 UC3FCTL - Bit 0-8
	rlwinm	%r0, 0, 0,24,24 # Mask on bit HVS
	cmplwi	%r0, 0x0
	bne	wait_hvs
	/* Get PEGOOD */
	lbz	%r0, -0x37F8(3) # 0x2FC808 UC3FCTL - Bit 0-8
	rlwinm	%r0, 0, 26,31,31 # Mask on bit PEGOOD
	stb	%r7, 0x71D6(3)
	stb	%r0, 0x71D7(3)
	li	%r0, 0xE2 # Buffer ready + DLC = 2
	sth	%r0, 0x71D0(3)
	/* Finish + Lock */
	li	%r0, 0x00 # Block=0x00, CSC=0, HSUS=0, PE=0, SES=0 and EHV=0
	sth	%r0, -0x37F6(3) # 0x2FC80A UC3FCTL - Block + Bit 24-31
	li	%r0, 0xFF
	stb	%r0, -0x37FD(3) # 0x2FC803 UC3FMCR - Protect
	bl	loop_main
end_command_0x03:

	/* Start command 0x04 */
	cmplwi	%r7, 0x04
	bne	end_command_0x04
	cmplwi	%r4, 2
	bne	loop_main # DLC is not 2
	#TODO
	bl	loop_main
end_command_0x04:

	/* Program command 0x05 */
	cmplwi	%r7, 0x05
	bne	end_command_0x05
	cmplwi	%r4, 8
	bne	loop_main # DLC is not 8
	#TODO
	bl	loop_main
end_command_0x05:

	/* Stop command 0x06 */
	cmplwi	%r7, 0x06
	bne	end_command_0x06
	cmplwi	%r4, 1
	bne	loop_main # DLC is not 1
	#TODO
	bl	loop_main
end_command_0x06:

	/* Reset command 0x07 */
	cmplwi	%r7, 0x07
	bne	loop_main
	cmplwi	%r4, 1
	bne	loop_main # DLC is not 1
	ba	0x100

