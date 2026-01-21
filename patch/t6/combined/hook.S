.section .text
.global hook_init, hook_loop, hook_timer_5ms

hook_init:
	bl	copy_calibration
.ifdef FLEXFUEL
	bl	flexfuel_init
.endif
.ifdef WIDEBAND
	bl	wideband_init
.endif
	# Pop link register from stack (Erase by patch in original code)
	lwz	%r0, 20(%r1)
	ba	hook_init_continue

hook_loop:
.ifdef FLEXFUEL
	bl	flexfuel
.endif
.ifdef WIDEBAND
	bl	wideband
.endif
	ba	hook_loop_continue

hook_timer_5ms:
.ifdef FLEXFUEL
	bl	flexfuel_5ms
.endif
.ifdef WIDEBAND
	bl	wideband_5ms
.endif
	# Load 10 (Erase by patch in original code)
	li	%r0, 10
	ba	hook_timer_5ms_continue
