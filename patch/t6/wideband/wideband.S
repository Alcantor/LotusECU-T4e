# Constants for narrow-band simulation
.set WB_RICH,  450 # (14.4 AFR - 10) / 2 * 1023 / 5 = 450.12
.set WB_LEAN,  512 # (15.0 AFR - 10) / 2 * 1023 / 5 = 511.50
.set NB_RICH,  184 # 0.90 V * 1023 / 5 = 184.14
.set NB_LEAN,   20 # 0.10 V * 1023 / 5 =  20.46
.set NB_STOI,   92 # 0.45 V * 1023 / 5 =  92.07

# Pre-O2 Input
.set ADC_WB_B1, (adc_dma_dest+44)
.set ADC_WB_B2, (adc_dma_dest+46)

# Expected calibration sequence values and threshold
.set WB_CAL_A, 341 # 1023 * 1 / 3 = 341.00
.set WB_CAL_B, 682 # 1023 * 2 / 3 = 682.00
.set WB_CAL_T, 102 # 0.50 V * 1023 / 5 = 102.30

# Allow up to 3 A for the wideband heater.
.set WB_MAX_I, 3000

# Sampling windows for calibration
.set WB_CALWIN, 9 # 9 = log2(2560ms / 5ms)

.section .data

.section .bss
.global wb_bank1, wb_bank2
.global wb_slope, wb_offset, wb_corr_adc

# One struct per bank
.comm wb_bank1, 20, 4
.comm wb_bank2, 20, 4

# Struct offset, total 20 bytes
.set wb_state,     0 # 0-2000 = Calibration, 2001 = Ready, 2002 = NB mode
.set wb_sampleA,   4 # u32_voltage_5/1023v
.set wb_sampleB,   8 # u32_voltage_5/1023v
.set wb_slope,    12 # Calibration slope, u16_factor_1/4096
.set wb_offset,   14 # Calibration offset, i16_voltage_5/1023v
.set wb_corr_adc, 16 # u16_voltage_5/1023v with correction !
.set wb_ht_th,    18 # u16_current_mA

.section .text
.global wideband_init, wideband, wideband_5ms

# Param r3 is pointer to bank struct
wideband_init_bank:
	# Start at state 0
	li	%r4, 0
	sth	%r4, wb_state(%r3)
	# Set sample accumulator to 0
	#li	%r4, 0
	stw	%r4, wb_sampleA(%r3)
	#li	%r4, 0
	stw	%r4, wb_sampleB(%r3)
	# Slope and offset to 0
	#li	%r4, 0
	sth	%r4, wb_slope(%r3)
	#li	%r4, 0
	sth	%r4, wb_offset(%r3)
	# Set 0 for wideband value
	#li	%r4, 0
	sth	%r4, wb_corr_adc(%r3)
	# Copy CAL_sensor_O2_heater_threshold
	lis	%r4, CAL_sensor_O2_heater_threshold@ha
	lhz	%r4, CAL_sensor_O2_heater_threshold@l(%r4)
	sth	%r4, wb_ht_th(%r3)
	blr

wideband_init:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Init bank 1 variables
	lis	%r3, wb_bank1@ha
	addi	%r3, %r3, wb_bank1@l
	bl	wideband_init_bank

	# Init bank 2 variables
	lis	%r3, wb_bank2@ha
	addi	%r3, %r3, wb_bank2@l
	bl	wideband_init_bank

	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr

# Param r3 is pointer to bank struct
# Param r4 is input adc value
# Return r3 as simulated narrow-band
wideband_bank:
	lhz	%r5, wb_state(%r3)
	cmplwi	%r5, 2001
	beq	wb_2
	cmplwi	%r5, 2002
	beq	wb_1
	# Simulate stoichiometric during calibration
	li	%r3, NB_STOI
	b	wb_6
wb_1:
	# No modification if a narrow-band is wired.
	srawi	%r3, %r4, 4
	b	wb_6
wb_2:
	# Wideband with narrow-band simulation
	srawi	%r4, %r4, 4
	lhz	%r5, wb_slope(%r3)
	mullw	%r4, %r4, %r5
	srwi	%r4, %r4, 12
	lha	%r5, wb_offset(%r3)
	add	%r4, %r4, %r5
	# Be sure to be positive
	cmpwi	%r4, 0
	bge	wb_3
	li	%r4, 0
wb_3:
	# Save corrected wideband for OBD request
	sth	%r4, wb_corr_adc(%r3)
	# If AFR is less/equal 14.4 then simulate a NB of 0.9v
	cmplwi	%r4, WB_RICH
	bgt	wb_4
	li	%r3, NB_RICH
	b	wb_6
wb_4:
	# If AFR is greater/equal 15.0 then simulate a NB of 0.1v
	cmplwi	%r4, WB_LEAN
	blt	wb_5
	li	%r3, NB_LEAN
	b	wb_6
wb_5:
	# If AFR is between 14.4-15.0 then compress and inverse the signal
	# r3 = NB_RICH - (r4 - WB_RICH) * (NB_RICH-NB_LEAN) / (WB_LEAN-WB_RICH)
	# Use reciprocal division
	subi	%r4, %r4, WB_RICH
	mulli	%r4, %r4, (NB_RICH-NB_LEAN)
	mulli	%r4, %r4, ((1<<20)/(WB_LEAN-WB_RICH))
	srwi	%r4, %r4, 20
	subfic	%r3, %r4, NB_RICH
wb_6:
	blr

wideband:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Correction and simulation bank 1
	lis	%r3, wb_bank1@ha
	addi	%r3, %r3, wb_bank1@l
	lis	%r4, ADC_WB_B1@ha
	lhz	%r4, ADC_WB_B1@l(%r4)
	bl	wideband_bank
	lis	%r4, sensor_adc_pre_O2_bank1@ha
	sth	%r3, sensor_adc_pre_O2_bank1@l(%r4)

	# Correction and simulation bank 2
	lis	%r3, wb_bank2@ha
	addi	%r3, %r3, wb_bank2@l
	lis	%r4, ADC_WB_B2@ha
	lhz	%r4, ADC_WB_B2@l(%r4)
	bl	wideband_bank
	lis	%r4, sensor_adc_pre_O2_bank2@ha
	sth	%r3, sensor_adc_pre_O2_bank2@l(%r4)

	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr

# Param r3 is pointer to bank struct
# Param r4 is input adc value
wideband_5ms_bank:
	# Only if state is less or equal 2000
	lhz	%r5, wb_state(%r3)
	cmplwi	%r5, 2000
	ble	timer_1
	blr
timer_1:
	# ADC Shift
	srawi	%r4, %r4, 4
	# Take 512 samples from 1.22s to 3.78s
	cmplwi	%r5, (500-(1<<(WB_CALWIN-1)))
	blt	timer_4
	cmplwi	%r5, (500+(1<<(WB_CALWIN-1)))
	bge	timer_2
	# If it's below than 1.16 V assume NB
	cmplwi	%r4, (WB_CAL_A-WB_CAL_T)
	blt	timer_5
	# If it's higher than 2.16 V assume NB
	cmplwi	%r4, (WB_CAL_A+WB_CAL_T)
	bgt	timer_5
	# Accumulate
	lwz	%r6, wb_sampleA(%r3)
	add	%r6, %r6, %r4
	stw	%r6, wb_sampleA(%r3)
	b	timer_4
timer_2:
	# Take 512 samples from 6.22s to 8.78s
	cmplwi	%r5, (1500-(1<<(WB_CALWIN-1)))
	blt	timer_4
	cmplwi	%r5, (1500+(1<<(WB_CALWIN-1)))
	bge	timer_3
	# If it's below than 2.83 V assume NB
	cmplwi	%r4, (WB_CAL_B-WB_CAL_T)
	blt	timer_5
	# If it's higher than 3.83 V assume NB
	cmplwi	%r4, (WB_CAL_B+WB_CAL_T)
	bgt	timer_5
	# Accumulate
	lwz	%r6, wb_sampleB(%r3)
	add	%r6, %r6, %r4
	stw	%r6, wb_sampleB(%r3)
	b	timer_4
timer_3:
	# Result at 10s
	cmplwi	%r5, 2000
	bne	timer_4
	# Load the samples into r6 and r7
	lwz	%r6, wb_sampleA(%r3)
	lwz	%r7, wb_sampleB(%r3)
	# Slope = (CAL_B - CAL_A) / (B - A)
	li	%r8, (WB_CAL_B-WB_CAL_A)
	slwi	%r8, %r8, (WB_CALWIN+12)
	sub	%r7, %r7, %r6
	divw	%r7, %r8, %r7
	sth	%r7, wb_slope(%r3)
	# Offset = CAL_A - (A * Slope)
	mullw	%r6, %r6, %r7
	srwi	%r6, %r6, (WB_CALWIN+12)
	subfic	%r6, %r6, WB_CAL_A
	sth	%r6, wb_offset(%r3)
	# Don't turn off the heater output unless it's more than 3 A.
	# The Spartan controller should be in charge of the heating process.
	li	%r6, WB_MAX_I
	sth	%r6, wb_ht_th(%r3)
timer_4:
	# Increment
	addi	%r5, %r5, 1
	sth	%r5, wb_state(%r3)
	blr
timer_5:
	# Change state
	li	%r5, 2002
	sth	%r5, wb_state(%r3)
	blr

wideband_5ms:
	# Push link register on stack
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)

	# Detection bank 1
	lis	%r3, wb_bank1@ha
	addi	%r3, %r3, wb_bank1@l
	lis	%r4, ADC_WB_B1@ha
	lhz	%r4, ADC_WB_B1@l(%r4)
	bl	wideband_5ms_bank

	# Detection bank 2
	lis	%r3, wb_bank2@ha
	addi	%r3, %r3, wb_bank2@l
	lis	%r4, ADC_WB_B2@ha
	lhz	%r4, ADC_WB_B2@l(%r4)
	bl	wideband_5ms_bank

	# Pop link register from stack
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr
