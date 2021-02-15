.section .text
.globl _start

_start:
	# Compute CRC32C
	#   DATA  : 0B AA AA AA LL LL LL LL
	#   RETURN: 0B CC CC CC CC

	/* CRC command 0x0B */
	cmplwi	%r21, 0x0B
	bne	end_command_0x0B
	cmplwi	%r24, 8
	bne	no_answer # DLC is not 8
	li	%r24, 5 # Answer 5 bytes
	li	%r0, -1 # Init value

	/* Lookup table at 0x3F8000 */
	lis	%r3, 0x3F8000@ha
	addi	%r3, %r3, 0x3F8000@l
crc_loop:
	cmplwi	%r22, 0
	beq	crc_finish

	/* Retrigger Watchdog */
	sth	%r29, -0x3FF2(%r30) # 0x2FC00E SWSR
	sth	%r28, -0x3FF2(%r30) # 0x2FC00E SWSR

	/* CRC32 Reflect */
	clrlwi	%r4, %r0, 24 # r4 = crc & 0xFF
	lbz	%r5, 0(%r20) # r5 = byte
	xor	%r4, %r4, %r5 # r4 = r4 ^ r5
	slwi	%r4, %r4, 2 # r4 = r4 * 4
	add	%r4, %r3, %r4
	lwz	%r4, 0(%r4)
	srwi	%r5, %r0, 8 # r5 = crc >> 8
	xor	%r0, %r4, %r5

	/* Next byte */
	addi	%r20, %r20, 1
	addi	%r22, %r22, -1
	b	crc_loop
crc_finish:
	li	%r4, -1
	xor	%r0, %r0, %r4 # Final XOR
	rlwimi	%r23, %r0, 24,8,31 # r23 = (r23 & 0xFF000000) | ((r0 >> 8) & 0x00FFFFFF)
	rlwinm	%r22, %r0, 24,0,7 # r22 = (r0 << 24) & 0xFF000000
	b	answer
end_command_0x0B:

no_answer:
	li	%r24, 0
answer:
	blr

