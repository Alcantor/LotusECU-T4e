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

	/* Init */
	bl	prepare_spi

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x03 # EEPROM Read command
	sth	%r0, 0x5180(%r30)
	srwi	%r0, %r20, 8 # EEPROM Address HIGH
	sth	%r0, 0x5182(%r30)
	rlwinm	%r0, %r20, 0,24,31 # EEPROM Address LOW
	sth	%r0, 0x5184(%r30)
	#li	%r31, 0 # EEPROM place holder for response (4x)
	sth	%r31, 0x5186(%r30)
	sth	%r31, 0x5188(%r30)
	sth	%r31, 0x518A(%r30)
	sth	%r31, 0x518C(%r30)

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0xBE # CONT = 1
	stb	%r0, 0x51C0(%r30)
	stb	%r0, 0x51C1(%r30)
	stb	%r0, 0x51C2(%r30)
	stb	%r0, 0x51C3(%r30)
	stb	%r0, 0x51C4(%r30)
	stb	%r0, 0x51C5(%r30)
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C6(%r30)

	/* Go */
	li	%r0, 0x0600 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 6, NEWQP = 0
	sth	%r0, 0x501C(%r30) # 0x30501C SPCR2
	bl	transmit_spi

	/* Answer */
	# Ignore 0x5140, 0x5142 and 0x5144 (Place holder for command)
	lhz	%r0, 0x5146(%r30)  # Receive RAM 0x305140-0x30517F - Byte 0
	rlwimi	%r23, %r0, 16,8,15 # r23 = (r23 & 0xFF00FFFF) | ((r0 << 16) & 0x00FF0000)
	lhz	%r0, 0x5148(%r30)  # Receive RAM 0x305140-0x30517F - Byte 1
	rlwimi	%r23, %r0, 8,16,23 # r23 = (r23 & 0xFFFF00FF) | ((r0 <<  8) & 0x0000FF00)
	lhz	%r0, 0x514A(%r30)  # Receive RAM 0x305140-0x30517F - Byte 2
	rlwimi	%r23, %r0, 0,24,31 # r23 = (r23 & 0xFFFFFF00) | ((r0 <<  0) & 0x000000FF)
	lhz	%r0, 0x514C(%r30)  # Receive RAM 0x305140-0x30517F - Byte 3
	rlwinm	%r22, %r0, 24,0,7  # r22 = (r0 << 24) & 0xFF000000
	b	answer
end_command_0x09:

	/* Write SPI EEPROM command 0x0A */
	cmplwi	%r21, 0x0A
	bne	end_command_0x0A
	cmplwi	%r24, 8
	bne	no_answer # DLC is not 8
	li	%r24, 1 # Answer 1 byte

	## Read status #########################################################
status:
	/* Init */
	bl	prepare_spi

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x05 # EEPROM Read Status Register command
	sth	%r0, 0x5180(%r30)
	#li	%r31, 0 # EEPROM place holder for response (1x)
	sth	%r31, 0x5182(%r30)

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0xBE # CONT = 1
	stb	%r0, 0x51C0(%r30)
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C1(%r30)

	/* Go */
	li	%r0, 0x0100 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 1, NEWQP = 0
	sth	%r0, 0x501C(%r30) # 0x30501C SPCR2
	bl	transmit_spi

	/* Is ready? */
	# Ignore 0x5140 (Place holder for command)
	lhz	%r0, 0x5142(%r30)  # Receive RAM 0x305140-0x30517F - Byte 0
	rlwinm	%r0, %r0, 0,31,31 # Mask on bit RDY
	cmplwi	%r0, 0
	bne	status

	## Write Enable ########################################################

	/* Put WP pin down through gpio? Not sure */
	li	%r0, 0
	bl	set_qdsck_gpio

	/* Init */
	bl	prepare_spi

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x06 # EEPROM Write Enable command
	sth	%r0, 0x5180(%r30)

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C0(%r30)

	/* Go */
	#li	%r31, 0x0000 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 0, NEWQP = 0
	sth	%r31, 0x501C(%r30) # 0x30501C SPCR2
	bl	transmit_spi

	## Write ###############################################################

	/* Init */
	bl	prepare_spi

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x02 # EEPROM Write command
	sth	%r0, 0x5180(%r30)
	srwi	%r0, %r20, 8 # EEPROM Address HIGH
	sth	%r0, 0x5182(%r30)
	rlwinm	%r0, %r20, 0,24,31 # EEPROM Address LOW
	sth	%r0, 0x5184(%r30)
	rlwinm	%r0, %r22,  8,24,31  # r0 = (r22 >> 24) & 0x000000FF
	sth	%r0, 0x5186(%r30) # Byte 1
	rlwinm	%r0, %r22, 16,24,31  # r0 = (r22 >> 16) & 0x000000FF
	sth	%r0, 0x5188(%r30) # Byte 2
	rlwinm	%r0, %r22, 24,24,31  # r0 = (r22 >>  8) & 0x000000FF
	sth	%r0, 0x518A(%r30) # Byte 3
	rlwinm	%r0, %r22,  0,24,31  # r0 = (r22 >>  0) & 0x000000FF
	sth	%r0, 0x518C(%r30) # Byte 4

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0xBE # CONT = 1
	stb	%r0, 0x51C0(%r30)
	stb	%r0, 0x51C1(%r30)
	stb	%r0, 0x51C2(%r30)
	stb	%r0, 0x51C3(%r30)
	stb	%r0, 0x51C4(%r30)
	stb	%r0, 0x51C5(%r30)
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C6(%r30)

	/* Go */
	li	%r0, 0x0600 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 6, NEWQP = 0
	sth	%r0, 0x501C(%r30) # 0x30501C SPCR2
	bl	transmit_spi

	## Write Disable #######################################################

	/* Init */
	bl	prepare_spi

	/* Fill Transmit RAM 0x305180-0x3051BF */
	li	%r0, 0x04 # EEPROM Write Disable command
	sth	%r0, 0x5180(%r30)

	/* Fill Command RAM 0x3051C0-0x3051DF */
	li	%r0, 0x3E # CONT = 0
	stb	%r0, 0x51C0(%r30)

	/* Go */
	#li	%r31, 0x0000 # SPIFIE=0, WREN = 0, WRTO = 0, ENDQP = 0, NEWQP = 0
	sth	%r31, 0x501C(%r30) # 0x30501C SPCR2
	bl	transmit_spi

	/* Put WP pin high through gpio? Not sure */
	li	%r0, 1
	bl	set_qdsck_gpio

	b	answer
end_command_0x0A:

no_answer:
	li	%r24, 0
answer:
	/* Restore return address */
	mtlr	%r3
	blr

set_qdsck_gpio:
	lhz	%r5, 0x5014(%r30) # 0x305014 PORTQS
	rlwimi	%r5, %r0, 2,29,29 # r5 = (r5 & 0xFFFFFFFB) | ((r0 << 2) & 0x00000004)
	sth	%r5, 0x5014(%r30)
	blr

set_tpu_b_hsr_14:
	lwz	%r5, 0x4418(%r30) # 0x304418 HSRRx_TPU_B Channel 15-0
	rlwimi	%r5, %r0, 28,2,3 # r5 = (r5 & 0xCFFFFFFF) | ((r0 << (14*2)) & 0x03000000)
	stw	%r5, 0x4418(%r30)
wait_tpu_hsr:
	lbz	%r5, 0x4418(%r30)
	cmplwi	%r5, 0
	bne	wait_tpu_hsr
	blr

prepare_spi:
	/* Configure SPI for EEPROM */
	lis	%r4, 0xA005@ha # MTSR = Master, BITS = 8, SPBR = 5 (2.8 MHz)
	addi	%r0, %r4, 0xA005@l
	sth	%r0, 0x5018(%r30) # 0x305018 SPCR0
	li	%r0, 0x1A03 # SPE = 0, DSCLK = 0x1A, DTL = 0x03
	sth	%r0, 0x501A(%r30) # 0x30501A SPCR1
	sth	%r31, 0x501C(%r30) # 0x30501C SPCR2
	sth	%r31, 0x501E(%r30) # 0x30501E SPCR3
	blr

transmit_spi:
	mflr	%r4
	/* Chip select */
	li	%r0, 2 # Drive Pin Low Channel 14
	bl	set_tpu_b_hsr_14
	/* Set SPE */
	lhz	%r0, 0x501A(%r30) # 0x30501A SPCR1
	ori	%r0, %r0, 0x8000 # SPE = 1
	sth	%r0, 0x501A(%r30) # 0x30501A SPCR1
wait_spif:
	/* Watchdog */
	sth	%r29, -0x3FF2(%r30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(%r30) # 0x2FC00E SWSR
	/* Read QSPI Status Register (SPSR) */
	lbz	%r0, 0x501F(%r30)
	rlwinm	%r0, %r0, 0,24,24 # Mask on bit SPIF
	cmplwi	%r0, 0
	beq	wait_spif
	/* Chip select */
	li	%r0, 1 # Drive Pin High Channel 14
	bl	set_tpu_b_hsr_14
	mtlr	%r4
	blr

