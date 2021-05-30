## Introduction

This is a bootloader with the CANstrap included. At every boot the startup sequence
will be delayed from approximately 500ms, so you have a chance to stop and get in
before the main program take the hand. This is very similar to the black dashboard
bootloader.

The CANstrap will be installed at 0x3000 between the Stage I and Stage II.

The default K-Line/CAN-Bus recovery routine of the bootloader are preserved.

In the black dashboard bootloader, there is only one stage... So the CANstrap is
installed at 0x9000 and takes the hand right after the reset vector.

## Files

 Files                 | Description
 ----------------------|------------
 build.py              | Build the file "bootldr.bin"
 white/bootldr.bin     | Bootloader from A128E6009F with the CANstrap in it.
 black/bootldr.bin     | Bootloader from A120E6501F with the CANstrap in it.

## Installation example for white dashboard (OBD Port, unlocked ECU).

This is a RISKY operation, I would not recommend to make it, except if you are
planning to make patch/modification of the main program.

	1. ./t4e.py -o ifp
	2. ./flasher.py -o vfp
	3. ./flasher.py -o e -b 0
	4. ./flasher.py -o vb -b 0
	5. ./flasher.py -o p -b 0 -D stage15/white/
	6. ./flasher.py -o v -b 0 -D stage15/white/
	7. ./flasher.py -o r

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
	5. ./flasher.py -o b &
	6. ./bdm-pi.py -o sfp
	7. ./flasher.py -o e -b 0
	8. ./flasher.py -o vb -b 0
	9. ./flasher.py -o p -b 0 -D stage15/black/
	10. ./flasher.py -o v -b 0 -D stage15/black/
	11. ./flasher.py -o r

	To 1-11: See the others examples

*Note: The parameter "-s black" is omitted here, the "bdm-pi.py" load only the
white version. This not a problem because we are alone on the bus.*

## Command line example (OBD Port, locked white ECU).

This is RISKY: The stage II will be overwritten.
This is COMPLICATE: Two different cables are needed. A VAG-COM and a CANable adapter.

	1. srec_cat flasher/canstrap-white.bin -binary -offset 0x4000 -o canstrap.srec -motorola -address-length 3 -header CANstrap
	2. ./srec2crp.py pack_t4e canstrap.srec canstrap.crp
	3. ./t4-white.py -f canstrap.crp
	4. [TURN CAR ON]
	5. [TURN CAR OFF]
	6. ./flasher.py -o b
	7. [TURN CAR ON]
	8. ./flasher.py -o e -b 0
	9. ./flasher.py -o p -b 0 -D stage15/white
	10. ./flasher.py -o c -b 0 -D stage15/white
	11. ./flasher.py -o dl -b 1 2
	12. ./flasher.py -o dl -b 1 2
	13. ./flasher.py -o r

	To 1: Do not but an offset below 0x4000 - Only Stage II can be overwritten.
	To 2: Convert the BIN file into an encrypted CRP file.
	To 3: With a VAG-COM adapter: Make your computer ready to answer the "Hello".
	To 4: Turn the CPU on. The flashing will automatically starts.
	To 5: At this point the Stage II is replaced with the CANstrap. You car won't run at this point!
	To 6: With a CAN-Bus adapter: Make your computer ready to answer the "Hello".
	To 7: Turn the CPU on. Enter into CANstrap.
	To 8: Erase the bootloader block (Stage I and II).
	To 9: Upload a complete bootloader (Stage I, II + stage 1.5).
	To 10: Verify the bootloader block (Using CRC).
	To 11: Download the calibration and the program.
	To 12: Verify the download.
	To 13: Reset.

## Usage example

Once you have a bootloader with the flasher in it, you can do everything to the
other blocks (Calibration and Main) more safely than ever and through the OBD Port.

	1. ./flasher.py -o b
	2. [TURN CAR ON]
	3. ./flasher.py -o ...

	To 1: Make flasher ready.
	To 2: Turn the CPU on.
	To 3: Whatever you want...

*Note: Add the parameter "-s black" if you are using the black version.*

## What's risky means...

You're are writing the bootloader, so if it fails the official recovery method
is also erased. A Lotus dealer won't be able to restore it through the OBD port.

You have to remove your ECU, unglue the cover and reprogram it with a BDM
programmer or a Raspberry Pi.

