## Introduction

This is a bootloader for the T4e with the CANstrap included. At every boot the
startup sequence will be delayed from approximately 500ms, so you have a chance
to stop and get in before the main program take the hand. This is very similar
to the black dashboard bootloader.

The CANstrap will be installed at 0x3000 between the Stage I and Stage II.

The default K-Line/CAN-Bus recovery routine of the bootloader are preserved.

In the black dashboard bootloader, there is only one stage... So the CANstrap is
installed at 0x9000 and takes the hand right after the reset vector.

## Files

 Files                 | Description
 ----------------------|------------
 white/bootldr.bin     | Bootloader from A128E6009F with the CANstrap in it.
 black/bootldr.bin     | Bootloader from A129E0002 with the CANstrap in it.

## Installation example for white dashboard (OBD Port, unlocked ECU).

This is a RISKY operation, I would not recommend to make it, except if you are
planning to make patch/modification of the main program.

	1. python3 -m lib.ltacc -o ifp
	2. python3 -m lib.flasher -o vfp
	3. python3 -m lib.flasher -o e -b 0
	4. python3 -m lib.flasher -o vb -b 0
	5. python3 -m lib.flasher -o p -b 0 -D stage15/white/
	6. python3 -m lib.flasher -o v -b 0 -D stage15/white/
	7. python3 -m lib.flasher -o r

	To 1: Install the flasher into the RAM.
	To 2: Verify the flasher itself.
	To 3: Erase the bootloader block. *** [TESTED] ***
	To 4: Verify the erasure.
	To 5: Program the bootloader block. *** [TESTED] ***
	To 6: Verify the bootloader block.
	To 7: Reset.

## Installation example for black dashboard (BDM Port, locked ECU).

Those commands are for the Raspberry Pi with a CAN Hat.

	1. ./bdm-pi.py -o pdh
	2. [TURN YOUR ECU ON]
	3. ./bdm-pi.py -o t
	4. ./bdm-pi.py -o ufp
	5. python3 -m lib.flasher -o b &
	6. ./bdm-pi.py -o sfp
	7. python3 -m lib.flasher -o e -b 0
	8. python3 -m lib.flasher -o vb -b 0
	9. python3 -m lib.flasher -o p -b 0 -D stage15/black/
	10. python3 -m lib.flasher -o v -b 0 -D stage15/black/
	11. python3 -m lib.flasher -o r

	To 1-11: See the others examples

*Note: The parameter "-s black" is omitted here, the "bdm-pi.py" load only the
white version. This not a problem because we are alone on the bus.*

## Usage example

Once you have a bootloader with the flasher in it, you can do everything to the
other blocks (Calibration and Main) more safely than ever and through the OBD Port.

	1. python3 -m lib.flasher -o b
	2. [TURN CAR ON]
	3. python3 -m lib.flasher -o ...

	To 1: Make flasher ready.
	To 2: Turn the CPU on.
	To 3: Whatever you want...

*Note: Add the parameter "-s black" if you are using the black version.*

## What's risky means...

You're are writing the bootloader, so if it fails the official recovery method
is also erased. A Lotus dealer won't be able to restore it through the OBD port.

You have to remove your ECU, unglue the cover and reprogram it with a BDM
programmer or a Raspberry Pi.

