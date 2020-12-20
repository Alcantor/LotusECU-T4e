## Introduction

This is a bootloader with the flasher included. At every boot the startup sequence
will be delayed from approximately 500ms, so you have a chance to stop and get in
before the main program take the hand.

The flasher will be installed at 0x3000 between the Stage I and Stage II.

## Files

	build.py: Build the file "bootldr.bin"
	bootldr.bin: Bootloader from ALS3M0240J with the flasher in it.

## Installation example

This is a RISKY operation, I would not recommend to make it, except if you are
planning to make patch/modification of the main program.

	1. ./t4e.py -o ifp
	5. ./flasher.py -o vfp
	6. ./flasher.py -o e -b 0
	7. ./flasher.py -o vb -b 0
	8. ./flasher.py -o p -b 0 -D stage15
	9. ./flasher.py -o v -b 0 -D stage15
	10. ./flasher.py -o r

	To 1: Install the flasher into the RAM.
	To 1: Verify the flasher itself.
	To 1: Erase the bootloader block. *** [TESTED] ***
	To 7: Verify the erasure.
	To 8: Program the bootloader block. *** [TESTED] ***
	To 9: Verify the bootloader block.
	To 10: Reset.

## Usage example

Once you have a bootloader with the flasher in it, you can do everything to the
other blocks (Calibration and Main) more safely than ever.

	1. ./flasher.py -o b
	2. [TURN CAR ON]
	3. ./flasher.py -o ...

	To 1: Make flasher ready.
	To 2: Turn the CPU on.
	To 3: Whatever you want...

