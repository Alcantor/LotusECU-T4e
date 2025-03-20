.section .text
.global hook_init, hook_loop, hook_timer_5ms

hook_init:
	bl	copy_calibration
.ifdef ACCUSUMP
	bl	accusump_init
.endif
.ifdef FLEXFUEL
	bl	flexfuel_init
.endif
.ifdef OBDOIL
	bl	obdoil_init
.endif
.ifdef WIDEBAND
	bl	wideband_init
.endif
	# Load 128 (Erase by patch in original code)
	li	%r0, 128
	ba	hook_init_continue

hook_loop:
.ifdef ACCUSUMP
	bl	accusump
.endif
.ifdef FLEXFUEL
	bl	flexfuel
.endif
.ifdef OBDOIL
	bl	obdoil
.endif
.ifdef WIDEBAND
	bl	wideband
.endif
	ba	hook_loop_continue

hook_timer_5ms:
.ifdef ACCUSUMP
	bl	accusump_5ms
.endif
.ifdef FLEXFUEL
	bl	flexfuel_5ms
.endif
.ifdef WIDEBAND
	bl	wideband_5ms
.endif
	# Load 10 (Erase by patch in original code)
	li	%r5, 10
	ba	hook_timer_5ms_continue
