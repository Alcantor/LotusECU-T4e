.section .text
.globl _start

_start:
loop:
	bla	0x02FC90
	bla	0x049B24
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x2562 # 0x3FDA9E
	lbz	%r5, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D31 # 0x3F92CF
	lbz	%r4, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x2561 # 0x3FDA9F
	lbz	%r0, 0(%r3)
	andc	%r0, %r4, %r0
	or	%r0, %r5, %r0
	clrlwi	%r0, %r0, 24
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D31 # 0x3F92CF
	stb	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D31 # 0x3F92CF
	lbz	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D3C # 0x3F92C4
	stb	%r0, 0(%r3)
	li	%r0, 1
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D30 # 0x3F92D0
	stb	%r0, 0(%r3)
	bla	0x02CE68
	bla	0x02D350
	bla	0x02D0C4
	li	%r0, 0
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6D30 # 0x3F92D0
	stb	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7F28 # 0x3F80D8
	lbz	%r0, 0(%r3)
	cmplwi	%r0, 0xFF
	beq	jump
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7F28 # 0x3F80D8
	lbz	%r3, 0(%r3)
	bla	0x041D04
	li	%r0, 0xFF
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7F28 # 0x3F80D8
	stb	%r0, 0(%r3)
jump:
	bla	0x02FE30
	bla	0x04B8A8
	bla	0x04BDEC
	bla	0x042078
	#bla	0x035C70

	# Fake RPM
	li	%r0, 4000
	lis	%r3, 0x40
	addi	%r3, %r3, -0x2DD0 # 0x3FD230
	sth	%r0, 0(%r3)

	bla	0x039874
	bla	0x030858
	bla	0x037CF8
	bla	0x038AD0
	bla	0x038130
	bla	0x03448C
	bla	0x03A248
	bla	0x03AE5C
	bla	0x036A68
	bla	0x038574
	bla	0x072150
	bla	0x03EEA4
	bla	0x033724
	bla	0x0313D0
	bla	0x03EB68
	bla	0x06EF2C
	bla	0x039048
	bla	0x03714C
	bla	0x03781C
	bla	0x039690 # ACIS
	bla	0x04093C
	bla	0x040B80
	bla	0x038944
	bla	0x06DAC8
	b	loop

