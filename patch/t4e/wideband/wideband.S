# Constants for narrow-band simulation
.set WB_RICH,  450 # (14.4 AFR - 10) / 2 * 1023 / 5 = 450.12
.set WB_LEAN,  512 # (15.0 AFR - 10) / 2 * 1023 / 5 = 511.50
.set NB_RICH,  184 # 0.90 V * 1023 / 5 = 184.14
.set NB_LEAN,   20 # 0.10 V * 1023 / 5 =  20.46
.set NB_STOI,   92 # 0.45 V * 1023 / 5 =  92.07

# Pre-O2 Input
.set ADC_WB,   0x304E86

# Expected calibration sequence values and threshold
.set WB_CAL_A, 341 # 1023 * 1 / 3 = 341.00
.set WB_CAL_B, 682 # 1023 * 2 / 3 = 682.00
.set WB_CAL_T, 102 # 0.50 V * 1023 / 5 = 102.30

# Allow up to 3 A for the wideband heater.
.set WB_MAX_I, 3000

# Sampling windows for calibration
.set WB_CALWIN,	9 # 9 = log2(2560ms / 5ms)

.section .data

.section .bss
.global wb_slope, wb_offset, wb_corr_adc, wb_ht_th

.lcomm	wb_state,    2, 2 # 0-2000 = Calibration, 2001 = Ready, 2002 = NB mode
.lcomm	wb_sampleA,  4, 4 # u32_voltage_5/1023v
.lcomm	wb_sampleB,  4, 4 # u32_voltage_5/1023v
.lcomm	wb_slope,    2, 2 # Calibration slope, u16_factor_1/4096
.lcomm	wb_offset,   2, 2 # Calibration offset, i16_voltage_5/1023v
.lcomm	wb_corr_adc, 2, 2 # u16_voltage_5/1023v with correction !
.lcomm	wb_ht_th,    2, 2 # u16_current_mA

.section .text
.global wideband_init, wideband, wideband_5ms

wideband_init:
	# Start at state 0
	li	%r3, 0
	lis	%r4, wb_state@ha
	sth	%r3, wb_state@l(%r4)
	# Set sample accumulator to 0
	#li	%r3, 0
	lis	%r4, wb_sampleA@ha
	stw	%r3, wb_sampleA@l(%r4)
	#li	%r3, 0
	lis	%r4, wb_sampleB@ha
	stw	%r3, wb_sampleB@l(%r4)
	# Slope and offset to 0
	#li	%r3, 0
	lis	%r4, wb_slope@ha
	sth	%r3, wb_slope@l(%r4)
	#li	%r3, 0
	lis	%r4, wb_offset@ha
	sth	%r3, wb_offset@l(%r4)
	# Set 0 for wibeband value
	#li	%r3, 0
	lis	%r4, wb_corr_adc@ha
	sth	%r3, wb_corr_adc@l(%r4)
	# Copy CAL_sensor_O2_heater_threshold
	lis	%r3, CAL_sensor_O2_heater_threshold@ha
	lhz	%r3, CAL_sensor_O2_heater_threshold@l(%r3)
	lis	%r4, wb_ht_th@ha
	sth	%r3, wb_ht_th@l(%r4)
	blr

wideband:
	lis	%r3, wb_state@ha
	lhz	%r3, wb_state@l(%r3)
	cmplwi	%r3, 2001
	beq	wb_2
	cmplwi	%r3, 2002
	beq	wb_1
	# Simulate stoichiometric during calibration
	li	%r3, NB_STOI
	b	wb_6
wb_1:
	# No modification if a narrow-band is wired.
	lis	%r3, ADC_WB@ha
	lhz	%r3, ADC_WB@l(%r3)
	b	wb_6
wb_2:
	# Wideband with narrow-band simulation
	lis	%r3, ADC_WB@ha
	lhz	%r3, ADC_WB@l(%r3)
	lis	%r4, wb_slope@ha
	lhz	%r4, wb_slope@l(%r4)
	mullw	%r3, %r3, %r4
	srwi	%r3, %r3, 12
	lis	%r4, wb_offset@ha
	lha	%r4, wb_offset@l(%r4)
	add	%r3, %r3, %r4
	# Be sure to be positive
	cmpwi	%r3, 0
	bge	wb_3
	li	%r3, 0
wb_3:
	# Save corrected wideband for OBD request
	lis	%r4, wb_corr_adc@ha
	sth	%r3, wb_corr_adc@l(%r4)
	# If AFR is less/equal 14.4 then simulate a NB of 0.9v
	cmplwi	%r3, WB_RICH
	bgt	wb_4
	li	%r3, NB_RICH
	b	wb_6
wb_4:
	# If AFR is greater/equal 15.0 then simulate a NB of 0.1v
	cmplwi	%r3, WB_LEAN
	blt	wb_5
	li	%r3, NB_LEAN
	b	wb_6
wb_5:
	# If AFR is between 14.4-15.0 then compress and inverse the signal
	# r3 = NB_RICH - (r3 - WB_RICH) * (NB_RICH-NB_LEAN) / (WB_LEAN-WB_RICH)
	# Use reciprocal division
	subi	%r3, %r3, WB_RICH
	mulli	%r3, %r3, (NB_RICH-NB_LEAN)
	mulli	%r3, %r3, ((1<<20)/(WB_LEAN-WB_RICH))
	srwi	%r3, %r3, 20
	subfic	%r3, %r3, NB_RICH
wb_6:
	lis	%r4, sensor_adc_pre_O2@ha
	sth	%r3, sensor_adc_pre_O2@l(%r4)
	blr

wideband_5ms:
	# Only if state is less or equal 2000
	lis	%r3, wb_state@ha
	lhz	%r3, wb_state@l(%r3)
	cmplwi	%r3, 2000
	ble	timer_1
	blr
timer_1:
	# Take 512 samples from 1.22s to 3.78s
	cmplwi	%r3, (500-(1<<(WB_CALWIN-1)))
	blt	timer_4
	cmplwi	%r3, (500+(1<<(WB_CALWIN-1)))
	bge	timer_2
	# Sample
	lis	%r4, ADC_WB@ha
	lhz	%r4, ADC_WB@l(%r4)
	# If it's below than 1.16 V assume NB
	cmplwi	%r4, (WB_CAL_A-WB_CAL_T)
	blt	timer_5
	# If it's higher than 2.16 V assume NB
	cmplwi	%r4, (WB_CAL_A+WB_CAL_T)
	bgt	timer_5
	# Accumulate
	lis	%r5, wb_sampleA@ha
	lwz	%r6, wb_sampleA@l(%r5)
	add	%r6, %r6, %r4
	#lis	%r5, wb_sampleA@ha
	stw	%r6, wb_sampleA@l(%r5)
	b	timer_4
timer_2:
	# Take 512 samples from 6.22s to 8.78s
	cmplwi	%r3, (1500-(1<<(WB_CALWIN-1)))
	blt	timer_4
	cmplwi	%r3, (1500+(1<<(WB_CALWIN-1)))
	bge	timer_3
	# Sample
	lis	%r4, ADC_WB@ha
	lhz	%r4, ADC_WB@l(%r4)
	# If it's below than 2.83 V assume NB
	cmplwi	%r4, (WB_CAL_B-WB_CAL_T)
	blt	timer_5
	# If it's higher than 3.83 V assume NB
	cmplwi	%r4, (WB_CAL_B+WB_CAL_T)
	bgt	timer_5
	# Accumulate
	lis	%r5, wb_sampleB@ha
	lwz	%r6, wb_sampleB@l(%r5)
	add	%r6, %r6, %r4
	#lis	%r5, wb_sampleB@ha
	stw	%r6, wb_sampleB@l(%r5)
	b	timer_4
timer_3:
	# Result at 10s
	cmplwi	%r3, 2000
	bne	timer_4
	# Load the samples into r4 and r5
	lis	%r4, wb_sampleA@ha
	lwz	%r4, wb_sampleA@l(%r4)
	lis	%r5, wb_sampleB@ha
	lwz	%r5, wb_sampleB@l(%r5)
	# Slope = (CAL_B - CAL_A) / (B - A)
	li	%r6, (WB_CAL_B-WB_CAL_A)
	slwi	%r6, %r6, (WB_CALWIN+12)
	sub	%r5, %r5, %r4
	divw	%r5, %r6, %r5
	lis	%r6, wb_slope@ha
	sth	%r5, wb_slope@l(%r6)
	# Offset = CAL_A - (A * Slope)
	mullw	%r4, %r4, %r5
	srwi	%r4, %r4, (WB_CALWIN+12)
	subfic	%r4, %r4, WB_CAL_A
	lis	%r5, wb_offset@ha
	sth	%r4, wb_offset@l(%r5)
	# Don't turn off the heater output unless it's more than 3 A.
	# The Spartan controller should be in charge of the heating process.
	li	%r4, WB_MAX_I
	lis	%r5, wb_ht_th@ha
	sth	%r4, wb_ht_th@l(%r5)
timer_4:
	# Increment
	addi	%r3, %r3, 1
	lis	%r4, wb_state@ha
	sth	%r3, wb_state@l(%r4)
	blr
timer_5:
	# Change state
	li	%r3, 2002
	lis	%r4, wb_state@ha
	sth	%r3, wb_state@l(%r4)
	blr
