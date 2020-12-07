.section .text
.globl _start

_start:
endloop:
	/* Retrigger Watchdog */
	lis	%r1, 0x30
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(1) # 0x2FC00E SWSR Register
	lis	%r0, 0x01
	addi	%r0, %r0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(1) # 0x2FC00E SWSR Register
	
	/* Endless loop */
	bl endloop
