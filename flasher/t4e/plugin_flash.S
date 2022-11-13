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
	cmplwi	%r21, 0x05
	bne	end_command_0x05
	cmplwi	%r24, 2
	bne	no_answer # DLC is not 2
	bl	sub_unlock
	/* Start erase sequence */
	li	%r0, 0x06 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=0
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	/* Erase */
	stw	%r0, 0(0) # Erase Interlock (Dummy write to the flash)
	li	%r0, 0x07 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=1
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_wait_hvs_and_answer
	/* Remove EHV */
	li	%r0, 0x06 # CSC=0, HSUS=0, PE=1, SES=1 and EHV=0
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_finish_and_lock
	b	answer
end_command_0x05:

	/* Start command 0x06 */
	cmplwi	%r21, 0x06
	bne	end_command_0x06
	cmplwi	%r24, 2
	bne	no_answer # DLC is not 2
	li	%r24, 1 # Answer 1 byte
	bl	sub_unlock
	/* Start program sequence */
	li	%r0, 0x02 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=0
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	b	answer
end_command_0x06:

	/* Program command 0x07 */
	cmplwi	%r21, 0x07
	bne	end_command_0x07
	cmplwi	%r24, 8
	bne	no_answer # DLC is not 8
	/* Program */
	stw	%r22, 0(%r20) # Write Interlock
	li	%r0, 0x03 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=1
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	bl	sub_wait_hvs_and_answer
	/* Remove EHV */
	li	%r0, 0x02 # CSC=0, HSUS=0, PE=0, SES=1 and EHV=0
	stb	%r0, -0x37F5(%r30) # 0x2FC80B UC3FCTL - Bit 24-31
	b	answer
end_command_0x07:

	/* Stop command 0x08 */
	cmplwi	%r21, 0x08
	bne	end_command_0x08
	cmplwi	%r24, 1
	bne	no_answer # DLC is not 1
	#li	%r24, 1 # Answer 1 byte
	bl	sub_finish_and_lock
	b	answer
end_command_0x08:

no_answer:
	li	%r24, 0
answer:
	/* Restore return address */
	mtlr	%r3
	blr

sub_unlock:
	/* Ensure small-block is disabled. (Enabled by some bootloader!) */
	stb	%r31, -0x37FC(%r30) # 0x2FC804 UC3FMCRE - Bit 0-7
	/* Blocks Mask */
	rlwinm  %r0, %r23, 16,24,31 # r0 = (r23 >> 16) & 0xFF
	/* Unlock */
	sth	%r0, -0x37F7(%r30) # 0x2FC809 UC3FCTL - SBBlock + Block
	not	%r0, %r0
	stb	%r0, -0x37FD(%r30) # 0x2FC803 UC3FMCR - Protect
	blr

sub_wait_hvs_and_answer:
	/* Erase or program could be long -> Retrigger Watchdog */
	sth	%r29, -0x3FF2(%r30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(%r30) # 0x2FC00E SWSR
	/* Wait */
	lbz	%r0, -0x37F8(%r30) # 0x2FC808 UC3FCTL - Bit 0-7
	rlwinm	%r0, %r0, 0,24,24 # Mask on bit HVS
	cmplwi	%r0, 0x0
	bne	sub_wait_hvs_and_answer
	/* Get PEGOOD and Answer */
	lbz	%r0, -0x37F8(%r30) # 0x2FC808 UC3FCTL - Bit 0-7
	rlwimi	%r23, %r0, 10,8,15 # r23 = (r23 & 0xFF00FFFF) | ((r0 << 10) & 0x00FF0000)
	li	%r24, 2 # Answer 2 bytes
	blr

sub_finish_and_lock:
	/* Finish + Lock */
	#li	%r31, 0x0000 # Block=0x00, CSC=0, HSUS=0, PE=0, SES=0 and EHV=0
	sth	%r31, -0x37F6(%r30) # 0x2FC80A UC3FCTL - Block + Bit 24-31
	li	%r0, 0xFF
	stb	%r0, -0x37FD(%r30) # 0x2FC803 UC3FMCR - Protect
	blr

