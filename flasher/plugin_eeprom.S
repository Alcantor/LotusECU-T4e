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
	cmplwi	%r16, 0x09
	bne	end_command_0x09
	cmplwi	%r13, 4
	bne	loop_main	# DLC is not 4

	/* Assign pin for SPI */
	li	%r0, 0x7B # Pins PCS3,2,1,0,MOSI,MISO for SPI
	stb	%r0, 0x5016(3) # 0x305016 PQSPAR
	li	%r0, 0x7E # Pins PCS3,2,1,0,MOSI as outputs
	stb	%r0, 0x5017(3) # 0x305017 DDRQST

	/* Configure TPU CH14 as discrete output */
	li	%r0, 0x02 # Discrete output
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
	srwi	%r0, 17, 8 # EEPROM Address HIGH
	sth	%r0, 0x5182(30)
	rlwinm	%r0, 17, 0,24,31 # EEPROM Address LOW
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
	stb	%r7, 0x71D6(30)
	lhz	%r0, 0x5140(30) # Receive RAM 0x305140-0x30517F - Byte 0
	stb	%r0, 0x71D7(30)
	lhz	%r0, 0x5142(30) # Receive RAM 0x305140-0x30517F - Byte 1
	stb	%r0, 0x71D8(30)
	lhz	%r0, 0x5144(30) # Receive RAM 0x305140-0x30517F - Byte 2
	stb	%r0, 0x71D9(30)
	lhz	%r0, 0x5146(30) # Receive RAM 0x305140-0x30517F - Byte 3
	stb	%r0, 0x71DA(30)
	li	%r0, 0xE5 # Buffer ready + DLC = 5
	sth	%r0, 0x71D0(30)
	b	loop_main
end_command_0x09:

	/* Write SPI EEPROM command 0x0A */
	cmplwi	%r16, 0x0A
	bne	end_command_0x0A
	cmplwi	%r13, 8
	bne	loop_main # DLC is not 8

	# TODO: Write %r15 into %r17

	/* Answer just with the command byte */
	stb	%r7, 0x71D6(30)
	li	%r0, 0xE1 # Buffer ready + DLC = 1
	sth	%r0, 0x71D0(30)
	b	loop_main
end_command_0x0A:

loop_main:
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

