.section .text
.globl _start

_start:
	/* Always 0x30 in r3 to minimize code footprint */
	lis	%r3, 0x30

	/* Disable interrupt */
	li	%r0, 0
	stw	%r0, -0x3FEC(3) # 0x2FC014 SIMASK1 Register
	stw	%r0, -0x3FB8(3) # 0x2FC048 SIMASK2 Register
	stw	%r0, -0x3FB4(3) # 0x2FC04C SIMASK3 Register

	/* Send "Hello!" trough CAN-Bus */
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x7100(3) # 0x307100 TouCAN A Buffer 0

	lis	%r0, 0xF400@ha # Destination address 0x7A0 << 5
	addi	%r0, 0, 0xF400@l
	sth	%r0, 0x7102(3)

	li	%r0, 0x4865 # Data: "He"
	sth	%r0, 0x7106(3)

	li	%r0, 0x6C6C # Data: "ll"
	sth	%r0, 0x7108(3)

	li	%r0, 0x6F21 # Data: "o!"
	sth	%r0, 0x710A(3)

	li	%r0, 0xC6 # Buffer ready + DLC = 6
	sth	%r0, 0x7100(3)

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
	#   DATA  : 03 MM MM
	#   RETURN: 03
	#
	# Start Block Programming
	#   DATA  : 04 MM MM
	#   RETURN: 04
	#
	# Program Block - Program 4 Bytes
	#   DATA  : 05 AA AA AA DD DD DD DD 
	#   RETURN: 05
	#
	# Stop Block Programming
	#   DATA  : 06
	#   RETURN: 06
	#
	# Reset:
	#   DATA  : 07
	#   RETURN: N/A

	/* Disable buffer 1-15 */
	li	%r0, 0x00 # Buffer disabled
	sth	%r0, 0x7110(3) # 0x307110 TouCAN A Buffer 1
	sth	%r0, 0x7120(3) # 0x307120 TouCAN A Buffer 2
	sth	%r0, 0x7130(3) # 0x307130 TouCAN A Buffer 3
	sth	%r0, 0x7140(3) # 0x307140 TouCAN A Buffer 4
	sth	%r0, 0x7150(3) # 0x307150 TouCAN A Buffer 5
	sth	%r0, 0x7160(3) # 0x307160 TouCAN A Buffer 6
	sth	%r0, 0x7170(3) # 0x307170 TouCAN A Buffer 7
	sth	%r0, 0x7180(3) # 0x307180 TouCAN A Buffer 8
	sth	%r0, 0x7190(3) # 0x307190 TouCAN A Buffer 9
	sth	%r0, 0x71A0(3) # 0x3071A0 TouCAN A Buffer 10
	sth	%r0, 0x71B0(3) # 0x3071B0 TouCAN A Buffer 11
	sth	%r0, 0x71C0(3) # 0x3071C0 TouCAN A Buffer 12
	sth	%r0, 0x71D0(3) # 0x3071D0 TouCAN A Buffer 13
	sth	%r0, 0x71E0(3) # 0x3071E0 TouCAN A Buffer 14
	sth	%r0, 0x71F0(3) # 0x3071F0 TouCAN A Buffer 15

	/* Configure receive address 0x60 */
	lis	%r0, 0xFFE0 # Reception Mask 0x7FF << 21
	stw	%r0, 0x7098(3) # 0x307098 Rx15MSK_A Register

	li	%r0, 0xC00 # Reception address 0x60 << 5
	sth	%r0, 0x71F2(3)

	li	%r0, 0x40 # Buffer activated
	sth	%r0, 0x71F0(3)

endloop:
	/* Retrigger Watchdog */
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register
	lis	%r0, 1
	addi	%r0, 0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register

	/* Has been data received */
	lhz	%r0, 0x71F0(3)
	rlwinm	%r4, 0, 0,24,27 # Mask Code
	cmplwi	%r4, 0x20 # Buffer Full
	beq	has_data
	cmplwi	%r4, 0x60 # Buffer Overrun (Has also data)
	bne	endloop
has_data:

	/* DLC > 0 */
	rlwinm	%r4, 0, 0,28,31 # Mask Length
	cmplwi	%r4, 0
	beq	endloop # DLC is 0

	/* Echo command 0x00 */
	lbz	%r5, 0x71F6(3)
	cmplwi	%r5, 0x00
	bne	end_command_0x01
	li	%r0, 0x80 # Buffer not ready + DLC = 0
	sth	%r0, 0x7100(3) # 0x307100 TouCAN A Buffer 0
	lwz	%r0, 0x71F6(3)
	stw	%r0, 0x7106(3)
	lwz	%r0, 0x71FA(3)
	stw	%r0, 0x710A(3)
	ori	%r0, 4, 0xC0 # Buffer ready + Copy DLC
	sth	%r0, 0x7100(3)
	bl	endloop
end_command_0x00:

	/* Read command 0x01 */
	cmplwi	%r5, 0x01
	bne	end_command_0x01
	cmplwi	%r4, 4
	bne	endloop # DLC is not 4
	lbz	%r0, 0x71F7(3)
	slw	%r0, 0, 16
	lhz	%r6, 0x71F8(3)
	or	%r6, 0, 6
	lwz	%r0, 0(6) # Read
	li	%r6, 0x80 # Buffer not ready + DLC = 0
	sth	%r6, 0x7100(3) # 0x307100 TouCAN A Buffer 0
	stb	%r5, 0x7106(3)
	stw	%r0, 0x7107(3) # Unaligned word could be bogus???
	li	%r6, 0xC6 # Buffer ready + DLC = 5
	sth	%r6, 0x7100(3)
	bl	endloop
end_command_0x01:

	/* Write command 0x02 */
	cmplwi	%r5, 0x02
	bne	end_command_0x02
	cmplwi	%r4, 8
	bne	endloop # DLC is not 8
	bl	endloop
	lbz	%r0, 0x71F7(3)
	slw	%r0, 0, 16
	lhz	%r6, 0x71F8(3)
	or	%r6, 0, 6
	lwz	%r0, 0x71FA(3)
	stw	%r0, 0(6) # Write
	li	%r6, 0x80 # Buffer not ready + DLC = 0
	sth	%r6, 0x7100(3) # 0x307100 TouCAN A Buffer 0
	stb	%r5, 0x7106(3)
	li	%r6, 0xC1 # Buffer ready + DLC = 1
	sth	%r6, 0x7100(3)
end_command_0x02:

	/* Erase command 0x03 */
	cmplwi	%r5, 0x03
	bne	end_command_0x03
	#TODO
	bl	endloop
end_command_0x03:

	/* Start command 0x04 */
	cmplwi	%r5, 0x04
	bne	end_command_0x04
	#TODO
	bl	endloop
end_command_0x04:

	/* Program command 0x05 */
	cmplwi	%r5, 0x05
	bne	end_command_0x05
	#TODO
	bl	endloop
end_command_0x05:

	/* Stop command 0x06 */
	cmplwi	%r5, 0x06
	bne	end_command_0x06
	#TODO
	bl	endloop
end_command_0x06:

	/* Reset command 0x07 */
	cmplwi	%r5, 0x07
	bne	endloop
	cmplwi	%r4, 1
	bne	endloop # DLC is not 1
	ba	0x1000

