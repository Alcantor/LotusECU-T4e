# This macro allows the computation of the relative offset of each calibration
# entries and export the result as OFF_ symbols.
.macro CALENTRY symbol
	\symbol:
	.equ OFF_\symbol, (\symbol-CAL_extra)
	.global \symbol, OFF_\symbol
.endm

.section .data

# Extra CALibration size
.equ CAL_extra_size, (CAL_extra_end-CAL_extra)

# The extra CALibration
CAL_extra:
.ascii	"XTRACAL3"
.ifdef FLEXFUEL
.include "../flexfuel/cal.inc.S"
.endif
CAL_extra_end:

.section .bss
.global CAL_base_extra

# Copy in RAM of extra CALibration.
.lcomm CAL_base_extra, CAL_extra_size

.section .text
.global copy_calibration

copy_calibration:
	# Copy extra calibration
	lis	%r3, CAL_base_extra@ha
	addi	%r3, %r3, CAL_base_extra@l
	subi	%r3, %r3, 4
	lis	%r4, CAL_extra@ha
	addi	%r4, %r4, CAL_extra@l
	subi	%r4, %r4, 4
	li	%r5, CAL_extra_size / 4
	mtctr	%r5
copy_loop:
	lwzu	%r5, 4(%r4)
	stwu	%r5, 4(%r3)
	bdnz	copy_loop
	blr
