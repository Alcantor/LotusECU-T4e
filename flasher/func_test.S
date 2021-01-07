.section .text
.globl _start

_start:
	/* Answer PPPPPPPP01020304 */
	mr	%r23, 22
	lis	%r22, 0x0102
	addi	%r22, 22, 0x0304
	li	%r24, 8 # Answer 8 bytes
	blr

