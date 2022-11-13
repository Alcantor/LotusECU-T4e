.section .data

CAL_signature:
.ascii	"XTRACAL0"
CAL_sensor_oil_pressure_gain:
.short	12500
CAL_sensor_oil_pressure_offset:
.short	-1250
CAL_accusump_X_engine_speed:
#	500, 1000, 4000, 8000   rpm
.byte	  0,   16,  112,  240 # u8_rspeed_125/4+500rpm
CAL_accusump:
#	 1,  1.5,  3.5,  3.5   bar
.byte	31,   46,  109,  109 # Pressure threshold in 32mbar

.section .bss

.lcomm	oil_pressure,	2 # i16_pressure_mbar

.section .text
.globl _start, accusump, hook_OBD_mode_0x22

_start:
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
	lhz	%r5, CAL_sensor_oil_pressure_offset@l(%r5)
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
	lhz	%r4, oil_pressure@l(%r4)
	extsh	%r4, %r4

	cmpw	%r4, %r3
	bge	accusump_close

accusump_open:
	/* Open accusump */
	lis	%r3, L9822E_outputs@ha
	lbz	%r4, L9822E_outputs@l(%r3)
	ori	%r4, %r4, 0x40
	stb	%r4, L9822E_outputs@l(%r3)
	b	accusump_return

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
	lis	%r3, oil_pressure@ha
	lhz	%r3, oil_pressure@l(%r3)
	sth	%r3, 0(%r5)
	addi	%r31, %r31, 2
	ba	hook_OBD_mode_0x22_jump

