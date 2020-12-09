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
	sth	%r0, 0x7100(3) # 0x307100 TouCAN A Tx Buffer 1

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

endloop:
	/* Retrigger Watchdog */
	li	%r0, 0x556C
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register
	lis	%r0, 1
	addi	%r0, 0, -0x55C7 # 0xAA39
	sth	%r0, -0x3FF2(3) # 0x2FC00E SWSR Register

	/* Endless loop */
	bl	endloop

