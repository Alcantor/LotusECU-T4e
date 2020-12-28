.section .text
.globl _start

_start:
	/* OBD Override */
	lis	%r4, 0x40
	addi	%r3, 4, 0x256C # 0x3FDA94, Specific to each version!!!
	lbz	%r0, 0(3)
	cmplwi	%r0, 0x16
	bne	normal
	addi	%r3, 4, 0x2566 # 0x3FDA9A, Specific to each version!!!
	lbz	%r0, 0(3)
	cmplwi	%r0, 0
	beq	close_accusump
	b	open_accusump

normal:
	/* r3 accusump table pointer */
	lis	%r3, 0x01
	addi	%r3, 3, 0x3CA0 # 0x013CA0

	/* r4 the RPM */
	lis	%r4, 0x40
	addi	%r4, 4, -0x2DD0 # 0x3FD230, Specific to each version!!!
	lhz	%r4, 0(4)
	li	%r0, 100
	divwu	%r4, 4, 0 /* Divide RPM by 100 */

	/* r5 the oil pressure */
	lis	%r5, 0x40
	addi	%r5, 5, -0x2F1C # 0x3FD0E4, Specific to each version!!!
	lhz	%r5, 0(5)
	srwi	%r5, 5, 2 /* From 11 Bits to 8 Bits value (Divide by 4) */

	/* r6 the selenoid output */
	lis	%r6, 0x40
	addi	%r6, 6, -0x6D31 # 0x3F92CF, Specific to each version!!!

	/* r7 Counter */
	li	%r7, 8
loop:
	addi	%r7, 7, -1

	/* Go through Y axis values */
	lbzx	%r0, 3, 7
	cmplw	%r4, 0
	bge	found_rpm_column
	cmplwi	%r7, 0
	bgt	loop

found_rpm_column:
	/* Get the threshold */
	addi	%r7, 7, 8 # Jump to the oil pressure values line
	lbzx	%r0, 3, 7
	cmplw	%r5, 0
	bge	close_accusump

open_accusump:
	/* Open accusump */
	lbz	%r0, 0(6) 
	ori	%r0, 0, 0x40
	stb	%r0, 0(6)
	blr

close_accusump:
	/* Close accusump */
	lbz	%r0, 0(6) 
	rlwinm	%r0, 0, 0,26,24
	stb	%r0, 0(6)
	blr

