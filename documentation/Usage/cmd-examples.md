# Command line usage.

## Files

 Files                 | Description
 ----------------------|------------
 gui.py                | Graphical interface.
 lib/ltacc.py          | Program to talk to the original UNLOCKED Software (Read/Write RAM)
 lib/flasher.py        | Program to talk to the flasher Software (Read/Write RAM+Flash+EEPROM)
 flasher/*.bin         | CAN-Bus Flasher for the MPC563
 lib/calibration.py    | Tool for CRC
 lib/crp01.py          | Convert a S-Record file into a CRP file (pre 2008).
 lib/crp01_uploader.py | Tool to upload a CRP file to a locked white ECU (Write Flash).
 lib/crp08.py          | Convert a BIN file into a CRP file (post 2008).
 lib/crp08_uploader.py | Tool to upload a CRP file to a locked black ECU (Write Flash).
 bdm-pi.py             | MPC5xx BDM Bit-Banging Tool for the Raspberry Pi (Debugger Base)

## Command line example (OBD Port, unlocked ECU)

	1. sudo ip link set can0 up type can bitrate 1000000
	2. python3 -m lib.ltacc -o dl -z 0 1 2 3 4
	3. python3 -m lib.ltacc -o v -z 0 1 2
	4. cp calrom.bin calrom.ori.bin
	5. [Modify calrom.bin with RomRaider]
	6. python3 -m lib.calibration sign calrom.ori.bin calrom.bin calrom.bin "MYTUNE"
	7. python3 -m lib.ltacc -o ifp
	8. python3 -m lib.flasher -o vfp
	9. python3 -m lib.flasher -o e -b 1
	10. python3 -m lib.flasher -o vb -b 1
	12. python3 -m lib.flasher -o p -b 1
	13. python3 -m lib.flasher -o v -b 1
	14. python3 -m lib.flasher -o r

	To 1: Turn CAN-Bus on [Linux/SocketCAN Only]
	To 2: Download the ECU like cybernet does.
	To 3: Verify the file from the previous step!
	To 4: Backup, backup, backup...
	To 5: Tune your engine!
	To 6: Sign the calibration with a fake date to match the original CRC. **
	To 7: Install the flasher into the RAM. *
	To 8: Verify the flasher itself.
	To 9: Erase the calibration block. *** [TESTED] ***
	To 10: Verify the erasure.
	To 12: Program the calibration block. *** [TESTED] ***
	To 13: Verify the calibration block.
	To 14: Reset.

*: This use a little hack (Stack Overwrite) to gain control, retry 4-5 times if it fails.

*: Tested with "BCroftT4E070 01/11/2005 Lotus EngV0078", "BCroftT4E080 20/02/2006 Lotus EngV0080", "BCroftT4E090 14/07/2006 Lotus EngV0091" and "BCroftT4E090 14/07/2006 Lotus EngV0093" yet.

**: Old version like V0078 and EngV0080 does not check the CRC at all.

**: The above example is for white dashboard only. Black dashboard is easier, because the CRC value is stored at the end of the calrom.

## Command line example (BDM Port, locked ECU)

If your ECU is completely fucked up, or unsupported by the t4e.py script (T4e ECU Black Dash),
you could use the BDM port with a Raspberry Pi. It's much slower than a true BDM-Programmer but
if you have a Raspberry Pi laying around, why not.

For that you need to remove you ECU from your car, open it and connect it correctly. It's only
loading the CAN-Bus Flasher with the BDM Port, so you also need to wire a CAN-Bus adapter.

Those commands are for the Raspberry Pi with a CAN Hat.

	1. ./bdm-pi.py -o pdh
	2. [TURN YOUR ECU ON]
	3. ./bdm-pi.py -o t
	4. ./bdm-pi.py -o ufp
	5. python3 -m lib.flasher -o b &
	6. ./bdm-pi.py -o sfp
	7. python3 -m lib.flasher -o dl -b 0 1 2
	8. python3 -m lib.flasher -o c -b 0 1 2

	To 1: Drive the DSCK pin high to enter BDM mode.
	To 2: Turn the CPU on.
	To 3: Test the connection by writing/reading a word. If it fail check your connections.
	To 4: Upload the flasher into the RAM.
	To 5: Bootstrap: The CAN-Flasher needs a answer within a short time, otherwise it will exit.
	To 6: Start the flasher.
	To 7: Download the ECU for example.
	To 8: Compare CRC of the file from the previous step!

*Note: At this point, you could install the stage15. This will avoid you to
re-open your ECU if you need to re-flash something.*

## Command line example (OBD Port, locked black ECU).

This example use the factory upload method (Like a Lotus Scan 3 would do). You
will lose your calibration (maps) with this method!

	1. [Get a calrom.bin file for your car]
	2. .python3 -m lib.calibration check calrom_original.bin
	3. [Modify calrom.bin with RomRaider]
	4. python3 -m lib.calibration unlock calrom_original.bin calrom.bin
	5. python3 -m lib.crp08 calrom calrom.bin calrom.crp
	6. python3 -m lib.crp08_uploader -f calrom.crp *** [TESTED only 1x BE CAREFUL] ***
	7. [TURN CAR ON]
	8. python3 -m lib.ltacc -s black -o dl -z 0 2 3 4
	9. python3 -m lib.ltacc -s black -o v -z 0 2

	To 1: Source a calrom.bin file. *
	To 2: Verify the calrom.bin that you find somewhere, the CRC must match!
	To 3: Modify the calibration if needed.
	To 4: Update the CRC and unlock the "live tuning" feature.
	To 5: Convert the BIN file into an encrypted CRP file.
	To 6: Make your computer ready to answer the "Hello" message from the ECU.
	To 7: Turn the CPU on. The flashing will automatically starts.
	To 8: Your ECU should be unlocked at this point. So download the "bootldr.bin" and "prog.bin" files.
	To 9: Verify the file from the previous step!

*: Because the factory bootloader can only upload files, you cannot read the
calibration of your ECU before overwriting it!

*Note: If your want to preserve your "calrom" but not your "prog" of your ECU, it's also possible.*

## Command line example (OBD Port, locked white ECU).

This is COMPLICATE: Two different cables are needed. A VAG-COM and a CANable adapter.

	1. for i in {0..63}; do echo 003FF000; done | xxd -r -p > lib/poison.bin
	2. srec_cat flasher/canstrap-white.bin -binary -offset 0x3FF000 lib/poison.bin -binary -offset 0x3FFF00 -o canstrap.srec -motorola -address-length 3 -header CANstrap
	3. python3 -m lib.crp01 T4e pack canstrap.srec flasher/canstrap.crp
	4. python3 -m lib.flasher -o b &
	5. python3 -m lib.crp01_uploader -f flasher/canstrap.crp
	6. [TURN CAR ON]
	7. python3 -m lib.flasher -o dl -b 0 1 2
	8. python3 -m lib.flasher -o c -b 0 1 2

	To 1: Create a file to poison the stack.
	To 2: Convert both BIN files into a SREC file.
	To 3: Convert the SREC file into an encrypted CRP file.
	To 4: With a CAN-Bus adapter: Make your computer ready to answer the "Hello" from the CANstrap.
	To 5: With a VAG-COM adapter: Make your computer ready to answer the "Hello" from the ECU.
	To 6: Turn the CPU on. The upload will automatically starts and it will hang because of the poison.
	To 7: Download the whole flash.
	To 8: Verify the download (with CRC).

*Note: At this point, you could install the stage15. This will give you an easy
access to re-flash something.*

## Debugging the MPC 5xx

With a small effort, the "bdm-pi.py" script could implements breakpoint, continue
und read/write registers functionality.

