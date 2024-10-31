.section .data

CAL_signature:
.ascii	"XTRACAL0"
CAL_sensor_oil_pressure_gain:
.short	12928
CAL_sensor_oil_pressure_offset:
.short	-1293
CAL_accusump_X_engine_speed:
#	500, 1000, 4000, 8000   rpm
.byte	  0,   16,  112,  240 # u8_rspeed_125/4+500rpm
CAL_accusump:
#	 1,  1.5,  3.5,  3.5   bar
.byte	31,   46,  109,  109 # Pressure threshold in 32mbar
CAL_accusump_max_open_time:
.byte	30 # Maximum open time to protect the coil in u8_time_s

.section .bss

.lcomm	oil_pressure,	2 # i16_pressure_mbar
.lcomm	timer,		2 # u16_time_5ms

.section .text
.globl _start, hook_init2, accusump, hook_timer_5ms, hook_OBD_mode_0x22

_start:
hook_init2:
	/* Initialize the timer to the value of the calibration */
	lis	%r3, CAL_accusump_max_open_time@ha
	lbz	%r3, CAL_accusump_max_open_time@l(%r3)
	mulli	%r3, %r3, 200
	lis	%r4, timer@ha
	sth	%r3, timer@l(%r4)
	blr

accusump:
	/* Push link register on stack */
	stwu	%r1, -8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)
  
	/* Oil pressure scaling */
	lis	%r3, sensor_adc_oil_pressure@ha
	lhz	%r3, sensor_adc_oil_pressure@l(%r3)
	lis	%r4, CAL_sensor_oil_pressure_gain@ha
	lhz	%r4, CAL_sensor_oil_pressure_gain@l(%r4)
	lis	%r5, CAL_sensor_oil_pressure_offset@ha
	lha	%r5, CAL_sensor_oil_pressure_offset@l(%r5)
	mullw	%r6, %r3, %r4
	srawi	%r6, %r6, 10
	addze	%r6, %r6
	add	%r6, %r6, %r5
	lis	%r7, oil_pressure@ha
	sth	%r6, oil_pressure@l(%r7)

	/* OBD Override */
	lis	%r3, OBD_mode_0x2F_state@ha
	lbz	%r3, OBD_mode_0x2F_state@l(%r3)
	cmplwi	%r3, 0x16
	bne	accusump_normal
	lis	%r3, OBD_mode_0x2F_value@ha
	lbz	%r3, OBD_mode_0x2F_value@l(%r3)
	cmplwi	%r3, 0
	beq	accusump_close
	b	accusump_open

accusump_normal:
	/* Close the accusump if ignition is off */
	lis     %r3, shutdown_flags@ha
	lhz     %r3, shutdown_flags@l(%r3)
	rlwinm  %r3, %r3, 0,31,31
	cmpwi   %r3, 0
	beq     accusump_close_reset_timer

       /* Compare oil pressure */
	li	%r3, 4
	lis	%r4, engine_speed_3@ha
	lbz	%r4, engine_speed_3@l(%r4)
	lis	%r5, CAL_accusump@ha
	addi	%r5, %r5, CAL_accusump@l
	lis	%r6, CAL_accusump_X_engine_speed@ha
	addi	%r6, %r6, CAL_accusump_X_engine_speed@l
	bla	lookup_2D_uint8_interpolated
	slwi	%r3, %r3, 5 # Multiply by 32
	lis	%r4, oil_pressure@ha
	lha	%r4, oil_pressure@l(%r4)
	cmpw	%r4, %r3
	bge	accusump_close_reset_timer

accusump_open_with_timer:
	/* If the time is out, close the accusump */
	lis	%r3, timer@ha
	lhz	%r3, timer@l(%r3)
	cmplwi	%r3, 0
	beq	accusump_close

accusump_open:
	/* Open accusump */
	lis	%r3, L9822E_outputs@ha
	lbz	%r4, L9822E_outputs@l(%r3)
	ori	%r4, %r4, 0x40
	stb	%r4, L9822E_outputs@l(%r3)
	b	accusump_return

accusump_close_reset_timer:
	/* Reset the timer to the value of the calibration */
	lis	%r3, CAL_accusump_max_open_time@ha
	lbz	%r3, CAL_accusump_max_open_time@l(%r3)
	mulli	%r3, %r3, 200
	lis	%r4, timer@ha
	sth	%r3, timer@l(%r4)

accusump_close:
	/* Close accusump */
	lis	%r3, L9822E_outputs@ha
	lbz	%r4, L9822E_outputs@l(%r3)
	rlwinm	%r4, %r4, 0,26,24
	stb	%r4, L9822E_outputs@l(%r3)

accusump_return:
	/* Pop link register from stack */
	lwz	%r0, 12(%r1)
	mtlr	%r0
	addi	%r1, %r1, 8
	blr

hook_timer_5ms:
	/* Decrement the timer every 5ms */
	/* It's ok to use r3, r4 and r5 here. */
	lis	%r3, timer@ha
	lhz	%r4, timer@l(%r3)
	cmplwi	%r4, 0
	beq	timeout
	subi	%r4, %r4, 1
	sth	%r4, timer@l(%r3)
timeout:
	/* Load 10 (Erase by patch in original code) */
	li	%r5, 10
	ba	hook_timer_5ms_continue

hook_OBD_mode_0x22:
	# %r31 is index in obd_resp
	# %r8 is the mode 0x22 pid

	# Store pointer to response array in %r4
	# Store current pointer to response byte in %r5
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r5, %r4, %r31

	/* Branching */
	cmplwi	%r8, 0x115C
	beq	OBD_mode_0x22_pid_0x115C

	/* Mask %r8 (Erase by patch in original code) */
	rlwinm	%r29, %r8, 0,16,31
	ba	hook_OBD_mode_0x22_continue

OBD_mode_0x22_pid_0x115C:
	/* Oil Pressure like GM pid 0x22115C (0x221154 Oil-Temp) */
	addi	%r31, %r31, 2 # Answer 2 bytes
	lis	%r3, oil_pressure@ha
	lha	%r3, oil_pressure@l(%r3)
	sth	%r3, 0(%r5)
	ba	hook_OBD_mode_0x22_jump

