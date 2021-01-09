_start:
	/* This is a initializing code, to be able to used plugin_eeprom from
	 * stage15. It's complicated because the Chip Select of the EEPROM is
	 * connected to a TPU pin. A microcode should be loaded to use the TPU.
	 */

	/* THIS DOES NOT WORD YET! */

	/* Read SPI EEPROM command 0x09 */
	cmplwi	%r21, 0x09
	bne	end_command_0x09
	cmplwi	%r24, 4
	bne	no_answer # DLC is not 4
	li	%r24, 5 # Answer 5 bytes

	/* Init TPU */
	li	%r0, 0x0480 # EMU = 1, SUPV = 1
	sth	%r0, 0x4400(30)
	# TODO: Soft reset of TPU?
	sth	%r31, 0x4428(30) # 0x304428 TPUMCR2
	li	%r0, 0x0053 # EPSCK = 1, EPSCK = 19
	sth	%r0, 0x442A(30) # 0x30442A TPUMCR3

	/* Configure TPU B CH14 as discrete output */
	# The automotive set of Freescale is used for TPU.
	li	%r0, 0x08 # Discrete output (8 << 0)
	stb	%r0, 0x440C(30) # 0x30440C CFSR0_TPU_B Channel 15-14

	/* Enable CH14 */
	li	%r0, 0x30 # High (3 << 4)
	stb	%r0, 0x441C(30) # 0x30441C CPR0_TPU_B Channel 15-12

	/* Assign pin for SPI */
	li	%r0, 0x7B # Pins PCS3,2,1,0,MOSI,MISO for SPI
	stb	%r0, 0x5016(30) # 0x305016 PQSPAR
	li	%r0, 0x7E # Pins PCS3,2,1,0,MOSI as outputs
	stb	%r0, 0x5017(30) # 0x305017 DDRQST
	
	blr
