.section .text
.globl _start

_start:
	/* Always 0x40 in r3 to minimize code footprint */
	lis	%r4, 0x40

	/* OBD Override */
	addi	%r4, 3, -0x256C # 0x3FDA94, Specific to each version!!!
	lbz	%r0, 0(4)
	cmplwi	%r0, 0x16
	bne	normal
	addi	%r4, 3, -0x2566 # 0x3FDA9A, Specific to each version!!!
	lbz	%r0, 0(4)
	cmplwi	%r0, 0
	beq	close_accusump
	b	open_accusump

normal:
	/* r4 accusump table pointer */
	lis	%r4, 0x01
	addi	%r4, 4, 0x3CA0 # 0x013CA0

	/* r5 the RPM */
	addi	%r5, 3, -0x2DD0 # 0x3FD230, Specific to each version!!!
	lhz	%r5, 0(5)
	li	%r0, 100
	divwu	%r5, 5, 0 /* Divide RPM by 100 */

	/* r6 the oil pressure */
	addi	%r6, 3, -0x2F1C # 0x3FD0E4, Specific to each version!!!
	lhz	%r6, 0(6)
	srwi	%r6, 6, 2 /* From 11 Bits to 8 Bits value (Divide by 4) */

	/* r7 the selenoid output pointer */
	addi	%r7, 7, -0x6D31 # 0x3F92CF, Specific to each version!!!

	/* r8 Counter */
	li	%r8, 8
loop:
	addi	%r8, 8, -1

	/* Go through Y axis values */
	lbzx	%r0, 4, 8
	cmplw	%r5, 0
	bge	found_rpm_column
	cmplwi	%r8, 0
	bgt	loop

found_rpm_column:
	/* Get the threshold */
	addi	%r8, 8, 8 # Jump to the oil pressure values line
	lbzx	%r0, 4, 8
	cmplw	%r6, 0
	bge	close_accusump

open_accusump:
	/* Open accusump */
	lbz	%r0, 0(7)
	ori	%r0, 0, 0x40
	stb	%r0, 0(7)
	blr

close_accusump:
	/* Close accusump */
	lbz	%r0, 0(7)
	rlwinm	%r0, 0, 0,26,24
	stb	%r0, 0(7)
	blr

