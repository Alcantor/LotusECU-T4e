.section .text
.globl _start

_start:
	/* Save return address */
	mflr	%r3

	# Erase Block
	#   DATA  : 05 MM (MM => Blocks Mask)
	#   RETURN: 05 0G (G => PEGOOD)
	#
	# Start Block Programming
	#   DATA  : 06 MM (MM => Blocks Mask)
	#   RETURN: 06
	#
	# Program Block - Program 4 Bytes
	#   DATA  : 07 AA AA AA DD DD DD DD 
	#   RETURN: 07 0G (G => PEGOOD)
	#
	# Stop Block Programming
	#   DATA  : 08
	#   RETURN: 08

	/* Erase command 0x05 */
	cmplwi	%r16, 0x05
	bne	end_command_0x05
	cmplwi	%r13, 2
	bne	loop_main # DLC is not 2
	bl	sub_unlock
	/* Start erase sequence */
	li	%r0, 0x06 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=0
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	/* Erase */
	stw	%r0, 0(0) # Erase Interlock (Dummy write to the flash)
	li	%r0, 0x07 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=1
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_wait_hvs_and_answer
	/* Remove EHV */
	li	%r0, 0x06 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=0
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_finish_and_lock
	b	loop_main
end_command_0x05:

	/* Start command 0x06 */
	cmplwi	%r16, 0x06
	bne	end_command_0x06
	cmplwi	%r13, 2
	bne	loop_main # DLC is not 2
	bl	sub_unlock
	/* Start program sequence */
	li	%r0, 0x02 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=0
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_answer1
	b	loop_main
end_command_0x06:

	/* Program command 0x07 */
	cmplwi	%r16, 0x07
	bne	end_command_0x07
	cmplwi	%r13, 8
	bne	loop_main # DLC is not 8
	/* Program */
	stw	%r15, 0(17) # Write Interlock
	li	%r0, 0x03 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=1
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_wait_hvs_and_answer
	/* Remove EHV */
	li	%r0, 0x02 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=0
	stb	%r0, -0x37F5(30) # 0x2FC80B UC3FCTL - Bit 24-31
	b	loop_main
end_command_0x07:

	/* Stop command 0x08 */
	cmplwi	%r16, 0x08
	bne	end_command_0x08
	cmplwi	%r13, 1
	bne	loop_main # DLC is not 1
	bl	sub_finish_and_lock
	bl	sub_answer1
	b	loop_main
end_command_0x08:

loop_main:
	mtlr	%r3
	blr

sub_unlock:
	/* Blocks Mask */
	rlwinm  %r0, 14, 16,24,31 # r0 = (r14 >> 16) & 0xFF
	/* Unlock */
	sth	%r0, -0x37F7(30) # 0x2FC809 UC3FCTL - SBBlock + Block
	not	%r0, 0
	stb	%r0, -0x37FD(30) # 0x2FC803 UC3FMCR - Protect
	blr

sub_wait_hvs_and_answer:
	/* Erase or program could be long -> Retrigger Watchdog */
	sth	%r29, -0x3FF2(30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(30) # 0x2FC00E SWSR
	/* Wait */
	lbz	%r0, -0x37F8(30) # 0x2FC808 UC3FCTL - Bit 0-8
	rlwinm	%r0, 0, 0,24,24 # Mask on bit HVS
	cmplwi	%r0, 0x0
	bne	sub_wait_hvs_and_answer
	/* Get PEGOOD and Answer */
	lbz	%r0, -0x37F8(30) # 0x2FC808 UC3FCTL - Bit 0-8
	rlwinm	%r0, 0, 26,31,31 # Mask on bit PEGOOD
	stb	%r16, 0x71D6(30)
	stb	%r0, 0x71D7(30)
	li	%r0, 0xE2 # Buffer ready + DLC = 2
	sth	%r0, 0x71D0(30)
	blr

sub_finish_and_lock:
	/* Finish + Lock */
	li	%r0, 0x0000 # Block=0x00, CSC=0, HSUS=0, PE=0, SES=0 and EHV=0
	sth	%r0, -0x37F6(3) # 0x2FC80A UC3FCTL - Block + Bit 24-31
	li	%r0, 0xFF
	stb	%r0, -0x37FD(3) # 0x2FC803 UC3FMCR - Protect
	blr

sub_answer1:
	/* Answer just with the command byte */
	stb	%r16, 0x71D6(30)
	li	%r0, 0xE1 # Buffer ready + DLC = 1
	sth	%r0, 0x71D0(30)
	blr

