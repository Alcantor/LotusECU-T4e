.section .data

.section .bss

.section .text
.globl _start, hook_OBD_mode_0x01, hook_narrow_sim

_start:
hook_OBD_mode_0x01:
	# %r30 is index in obd_req
	# %r31 is index in obd_resp

	# Store current request byte in %r3
	lis	%r3, obd_req@ha
	addi	%r3, %r3, obd_req@l
	add	%r3, %r3, %r30
	lbz	%r3, 0(%r3)

	# Store pointer to response array in %r4
	# Store current pointer to response byte in %r5
	lis	%r4, obd_resp@ha
	addi	%r4, %r4, obd_resp@l
	add	%r5, %r4, %r31

	# Branching
	cmplwi	%r3, 0x20
	beq	OBD_mode_0x01_pid_0x20
	cmplwi	%r3, 0x24
	beq	OBD_mode_0x01_pid_0x24

	# Mask %r30 (Erase by patch in original code)
	rlwinm	%r0, %r30, 0,24,31
	ba	hook_OBD_mode_0x01_continue

OBD_mode_0x01_pid_0x20:
	# Available PID 0x21-0x40
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r5)

	lis	%r3, 0x90062001@ha
	addi	%r3, %r3, 0x90062001@l
	stw	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump

OBD_mode_0x01_pid_0x24:
	# Wideband Lambda
	addi	%r31, %r31, 5 # Answer 5 bytes
	stb	%r3, 0(%r5)

	# Read Pre-O2 input (0V = 10 AFR, 5V = 20 AFR)
	lis	%r3, 0x304E86@ha
	lhz	%r3, 0x304E86@l(%r3)

	# Byte CD
	# CD = ADC/1024*5*65536/8 = ADC*40
	mulli	%r0, %r3, 40
	sth	%r0, 3(%r5)

	# Byte AB = (0.68 + ADC/1024*0.68) * 65536/2 = (557056 + ADC*544) / 25
	mulli	%r3, %r3, 544
	addis	%r3, %r3, 557056@ha
	addi	%r3, %r3, 557056@l
	li	%r0, 25
	divw	%r3, %r3, %r0
	sth	%r3, 1(%r5)

	ba	hook_OBD_mode_0x01_jump

hook_narrow_sim:
	# Simulate a Narrow-Band signal from the Wideband sensor.
	cmplwi	%r0, 451
	bgt	not_rich
	# If AFR is less/equal 14.4 then simulate a NB of 0.9v
	li	%r0, 184
	ba	hook_narrow_sim_continue
not_rich:
	cmplwi	%r0, 512
	blt	not_lean
	# If AFR is greater/equal 15.0 then simulate a NB of 0.1v
	li	%r0, 20
	ba	hook_narrow_sim_continue
not_lean:
	# If AFR is between 14.4-15.0 then compress the signal
	li	%r3, 451
	sub	%r0, %r0, %r3
	mulli	%r0, %r0, (184-20) # Out range 0.1 to 0.9 Volt
	li	%r3, (512-451) # In range 14.4 to 15.0 AFR
	divw	%r0, %r0, %r3
	li	%r3, 184
	sub	%r0, %r3, %r0 # Inverse the curve
	ba	hook_narrow_sim_continue

