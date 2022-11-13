.section .data

CAL_misc_accusump_threshold:
.byte	0x0A, 0x14, 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50 # RPM
.byte	0x2E, 0x38, 0x43, 0x4D, 0x57, 0x61, 0x61, 0x61 # Pressure

.section .text
.globl _start

_start:
	/* Always 0x40 in r3 to minimize code footprint */
	lis	%r3, 0x40

	/* r7 the selenoid output pointer */
	addi	%r7, %r3, -0x6A79 # 0x3F9587, Specific to each version!!!

	/* OBD Override (r7 needed!) */
	addi	%r4, %r3, -0x2154 # 0x3FDEAC, Specific to each version!!!
	lbz	%r0, 0(%r4)
	cmplwi	%r0, 0x16
	bne	normal
	addi	%r4, %r3, -0x214E # 0x3FDEB2, Specific to each version!!!
	lbz	%r0, 0(%r4)
	cmplwi	%r0, 0
	beq	close_accusump
	b	open_accusump

normal:
	/* r4 accusump table pointer */
	lis	%r4, CAL_misc_accusump_threshold@ha
	addi	%r4, %r4, CAL_misc_accusump_threshold@l

	/* r5 the RPM */
	addi	%r5, %r3, -0x29B4 # 0x3FD64C, Specific to each version!!!
	lhz	%r5, 0(%r5)
	li	%r0, 50
	divwu	%r5, %r5, %r0 /* Divide RPM by 50 */

	/* r6 the oil pressure */
	addi	%r6, %r3, -0x2B02 # 0x3FD4FE, Specific to each version!!!
	lhz	%r6, 0(%r6)
	srwi	%r6, %r6, 2 /* From 10 Bits to 8 Bits value (Divide by 4) */

	/* r8 Counter */
	li	%r8, 8
loop:
	addi	%r8, %r8, -1

	/* Go through Y axis values */
	lbzx	%r0, %r4, %r8
	cmplw	%r5, %r0
	bge	found_rpm_column
	cmplwi	%r8, 0
	bgt	loop

found_rpm_column:
	/* Get the threshold */
	addi	%r8, %r8, 8 # Jump to the oil pressure values line
	lbzx	%r0, %r4, %r8
	cmplw	%r6, %r0
	bge	close_accusump

open_accusump:
	/* Open accusump */
	lbz	%r0, 0(%r7)
	ori	%r0, %r0, 0x40
	stb	%r0, 0(%r7)
	blr

close_accusump:
	/* Close accusump */
	lbz	%r0, 0(%r7)
	rlwinm	%r0, %r0, 0,26,24
	stb	%r0, 0(%r7)
	blr

