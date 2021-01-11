.section .text
.globl _start

_start:
loop:
	bla	0x03221C
	bla	0x04BEFC
	lis	%r3, 0x40
	addi	%r3, %r3, -0x214A # 0x3FDEB6
	lbz	%r5, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A79 # 0x3F9587
	lbz	%r4, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x2149 # 0x3FDEB7
	lbz	%r0, 0(%r3)
	andc	%r0, %r4, %r0
	or	%r0, %r5, %r0
	clrlwi	%r0, %r0, 24
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A79 # 0x3F9587
	stb	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A79 # 0x3F9587
	lbz	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A84 # 0x3F957C
	stb	%r0, 0(%r3)
	li	%r0, 1
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A78 # 0x3F9588
	stb	%r0, 0(%r3)
	bla	0x02F420
	bla	0x02F8C8
	bla	0x02F67C
	li	%r0, 0
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x6A78 # 0x3F9588
	stb	%r0, 0(%r3)
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7EA8 # 0x3F8158
	lbz	%r0, 0(%r3)
	cmplwi	%r0, 0xFF
	beq	jump1
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7EA8 # 0x3F8158
	lbz	%r3, 0(%r3)
	bla	0x044308
	li	%r0, 0xFF
	lis	%r3, 0x40 # '@'
	addi	%r3, %r3, -0x7EA8 # 0x3F8158
	stb	%r0, 0(%r3)
jump1:
	bla	0x0323BC
	bla	0x04DC80
	bla	0x04E1C4
	bla	0x04467C
	#bla	0x038238 # Inputs? Disable RPM Reading

	# Fake RPM
	li	%r0, 4400
	lis	%r3, 0x40
	addi	%r3, %r3, -0x29B4	
	sth	%r0, 0(%r3)

	bla	0x03BE3C
	bla	0x032DE4
	bla	0x03A2C0
	bla	0x03B098
	bla	0x03A6F8
	bla	0x036A8C
	bla	0x03C7F8
	bla	0x03D40C
	bla	0x039030
	bla	0x03AB3C
	bla	0x041498
	bla	0x035D78
	bla	0x03395C
	bla	0x041154
	bla	0x070CD0
	bla	0x03B610
	bla	0x039714
	bla	0x039DE4
	bla	0x03BC58 # ACIS ??
	bla	0x042F30
	bla	0x043174
	bla	0x03AF0C
	bla	0x06F818
	b	loop

