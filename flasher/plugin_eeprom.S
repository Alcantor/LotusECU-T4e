.section .text
.globl _start

_start:
	/* Save return address */
	mflr	%r3

	# Read SPI EEPROM - Read 4 Bytes
	#   DATA  : 09 AA AA AA
	#   RETURN: 09 DD DD DD DD
	#
	# Write SPI EEPROM - Write 4 Bytes
	#   DATA  : 10 AA AA AA DD DD DD DD
	#   RETURN: 10

	/* Read SPI EEPROM command 0x09 */
	cmplwi	%r21, 0x09
	bne	end_command_0x09
	cmplwi	%r24, 4
	bne	no_answer # DLC is not 4
	li	%r24, 5 # Answer 5 bytes

	/* Assign pin for SPI */
	li	%r0, 0x7B # Pins PCS3,2,1,0,MOSI,MISO for SPI
	stb	%r0, 0x5016(30) # 0x305016 PQSPAR
	li	%r0, 0x7E # Pins PCS3,2,1,0,MOSI as outputs
	stb	%r0, 0x5017(30) # 0x305017 DDRQST

	/* Configure TPU CH14 as discrete output */
	# The automotive set of Freescale is used for TPU.
	li	%r0, 0x88 # Discrete output (2x)
	stb	%r0, 0x440C(30) # 0x30440C CFSR0_TPU_B Channel 15-14

	/* Configure SPI for EEPROM */
	lis	%r0, 0xA005@ha # MTSR = Master, BITS = 8, SPBR = 5 (2.8 MHz)
	addi	%r0, 0, 0xA005@l
	sth	%r0, 0x5018(30) # 0x305018 SPCR0

	li	%r0, 0x1A03 # SPE = 0, DSCLK = 0x1A, DTL = 0x03
	sth	%r0, 0x501A(30) # 0x30501A SPCR1

	sth	%r31, 0x501C(30) # 0x30501C SPCR2
	sth	%r31, 0x501E(30) # 0x30501E SPCR3

	/* Chip select */
	li	%r0, 0x20 # Drive Pin Low Channel 14
	bl	set_tpu_b_15_12

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x03 # EEPROM Read command
	sth	%r0, 0x5180(30)
	clrlwi  %r0, 0, 24
	srwi	%r0, 20, 8 # EEPROM Address HIGH
	sth	%r0, 0x5182(30)
	rlwinm	%r0, 20, 0,24,31 # EEPROM Address LOW
	sth	%r0, 0x5184(30)
	li	%r0, 0 # EEPROM place holder for response (4x)
	sth	%r0, 0x5186(30)
	sth	%r0, 0x5188(30)
	sth	%r0, 0x518A(30)
	sth	%r0, 0x518C(30)

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0xBE # CONT = 1
	stb	%r0, 0x51C0(30)
	stb	%r0, 0x51C1(30)
	stb	%r0, 0x51C2(30)
	stb	%r0, 0x51C3(30)
	stb	%r0, 0x51C4(30)
	stb	%r0, 0x51C5(30)
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C6(30)
		
	li	%r0, 0x0600 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 6, NEWQP = 0
	sth	%r0, 0x501C(30) # 0x30501C SPCR2

	lhz	%r0, 0x501A(30) # 0x30501A SPCR1
	ori	%r0, 0, 0x8000 # SPE = 1
	sth	%r0, 0x501A(30) # 0x30501A SPCR1

	/* Wait */
	bl	wait_spif

	/* Chip select */
	li	%r0, 0x10 # Drive Pin High Channel 14
	bl	set_tpu_b_15_12

	/* Answer */
	lhz	%r0, 0x5146(30)  # Receive RAM 0x305140-0x30517F - Byte 0
	rlwimi	%r23, 0, 16,8,15 # r23 = (r23 & 0xFF00FFFF) | ((r0 << 16) & 0x00FF0000)
	lhz	%r0, 0x5148(30)  # Receive RAM 0x305140-0x30517F - Byte 1
	rlwimi	%r23, 0, 8,16,23 # r23 = (r23 & 0xFFFF00FF) | ((r0 <<  8) & 0x0000FF00)
	lhz	%r0, 0x514A(30)  # Receive RAM 0x305140-0x30517F - Byte 2
	rlwimi	%r23, 0, 0,24,31 # r23 = (r23 & 0xFFFFFF00) | ((r0 <<  0) & 0x000000FF)
	lhz	%r0, 0x514C(30)  # Receive RAM 0x305140-0x30517F - Byte 3
	rlwinm	%r22, 0, 24,0,7  # r22 = (r0 << 24) & 0xFF000000
	b	answer
end_command_0x09:

	/* Write SPI EEPROM command 0x0A */
	cmplwi	%r21, 0x0A
	bne	end_command_0x0A
	cmplwi	%r24, 8
	bne	no_answer # DLC is not 8
	li	%r24, 1 # Answer 1 byte

	# TODO: Write %r22 into %r20

	b	answer
end_command_0x0A:

no_answer:
	li	%r24, 0
answer:
	/* Restore return address */
	mtlr	%r3
	blr

set_tpu_b_15_12:
	stb	%r0, 0x4418(30) # 0x304418 HSRR0_TPU_B Channel 15-12
wait_tpu_hsr:
	lbz	%r0, 0x4418(30)
	cmplwi	%r0, 0
	bne	wait_tpu_hsr
	blr

wait_spif:
	/* Watchdog */
	sth	%r29, -0x3FF2(30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(30) # 0x2FC00E SWSR
	/* Read QSPI Status Register (SPSR) */
	lbz	%r0, 0x501F(30)
	rlwinm	%r0, 0, 0,24,24 # Mask on bit SPIF
	cmplwi	%r0, 0
	beq	wait_spif
	blr

