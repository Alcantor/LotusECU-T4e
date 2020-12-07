.section .text
.globl _start

_start:
	/* Disable interrupt */
	li	%r0, 0
	lis	%r3, 0x30
	stw	%r0, -0x3FEC(3) # 0x2FC014 SIMASK1 Register
	stw	%r0, -0x3FB8(3) # 0x2FC048 SIMASK2 Register
	stw	%r0, -0x3FB4(3) # 0x2FC04C SIMASK3 Register

endloop:
	/* Retrigger Watchdog */
	lis	%r3, 0x30
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register
	lis	%r0, 0x01
	addi	%r0, 0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register
	
	/* Endless loop */
	bl	endloop
