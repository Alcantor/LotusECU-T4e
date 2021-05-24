# Lotus T4e Flasher

## Disclaimer

***Use it at your own RISK.***

## Introduction

This is my attempt to tune my Lotus Exige S2 (T4e ECU White Dash).

It's based on the work of [Obeisance] and [Cybernet].

[Obeisance]: https://www.lotustalk.com/threads/daft-disassembly.352193/
[Cybernet]: https://www.lotustalk.com/threads/t4e-ecu-editor-preview.372258/

I didn't have a Arduino with a CAN-Shield but I have an USB-to-CAN Adapter.
So I made my own Python-Script (Linux and Windows) to make the dump. It should also work
with a RaspberryPi and a CAN Hat (SocketCAN Driver).

After that I've realized that the Calibration ROM located at 0x10000 looks like
identical to the T4 ECU at address 0x70000. So I've edited the XML to use the
new offset.

But how to upload the modification back? Hum, after somes hours of disassembling,
I've figured out how to write to the RAM but not to the Flash.

Well If I can write to the RAM, I'am allowed to upload my own program. That's
what I've done. So I've write a small CAN-Bus Flasher to write to the Flash
through the OBD Port.

My final goal was to control my accusump with the T4e ECU, that was not possible
without patching the main program. See folder [accusump].

To be able to patch the main program more safely I've included the flasher into
the bootloader. See folder [stage15].

After that I went a little further by looking at the ECU Black Dash.

[accusump]:https://github.com/Alcantor/LotusECU-T4e/tree/master/accusump
[stage15]:https://github.com/Alcantor/LotusECU-T4e/tree/master/stage15

## Licensing

Under [CC-NC-SA].

[CC-NC-SA]: https://creativecommons.org/licenses/by-nc-sa/4.0/

## Factory Method 

### Pre 2008

The T4 and the T4e ECU on the Lotus with white dashboard (Instrument Cluster)
has a bootloader split into 2 parts: Stage 1 and 2.

The stage 1 can update the stage 2 and is enabled only if the CRC of the stage 2
is wrong.

The stage 2 accepts an encrypted .CRP file and can update itself, the
calibration or the software. Only writing with K-Line, no reading...

It would be possible the modify the stage 2 to have read functionality.
If you want to flash using that method, try the [Daft_LotusT4_OBD].

[Daft_LotusT4_OBD]: https://github.com/Obeisance/Daft_LotusT4_OBD

### Post 2008

The T4e of the black dashboard cars has another bootloader which does the
reprogramming with CAN-Bus (500 kbit/s).

This bootloader accepts an encrypted .CRP file and can update the calibration,
the software or the EEPROM. Only writing with CAN-Bus, no reading...

### CRP Files

ECU Updates from Lotus are .CRP files. Somes are available on the [VCIS].
Most of them are included in the Lotus TechCentre or Lotus Scan 3.

The structure of the .CRP files has completely change in 2008.

[VCIS]: https://vsic.lotuscars.com/

## Live tuning access [2006-2008]

For most of the white dashboard, there is an access provided by the main program
trough CAN-BUS (1 Mbit/s). It's intended for "live tuning" and not for
reprogramming the ECU, but with somes hacks it could be use for this purpose.

This access has been definitively locked on the black dashboard. But it's
possible to re-enable it, with a BDM access or a modified .CRP file.

My little hack is not guaranteed to work on all software versions of the
ECU but when it works it's very reliable (A good CAN-Bus adapter is mandatory).

## Prerequisite

The [Python 3] interpreter with the [python-can] module and a compatible [CAN-BUS adapter].

The CANable (with slcan firmware) is very simple to use, but it has a bottleneck
with the serial interface, and does not work well with the "t4e.py" script.
In contrario the "flasher.py" works flawless (but slowly) with this adapter
because it doesn't make bulk read/write. So if you still want to use this adapter,
use the download function of the "flasher.py" and not from the "t4e.py".

The CANable (with CandleLight firmware) is great but unsupported under Windows yet.
This could change in a near future (see develop of python-can).

The IXXAT USB-to-CAN Adapter is easy to use and reliable but expensive.

The Raspberry-Pi + CAN-Hat is cheap and you can use it as a BDM-Programmer, but
it's not really reliable. The MCP2515 has only two receive buffers and the linux
driver for it doesn't implement HW-Filtering ([patch] ?). This leads to packet
loss, especially for old versions (Like V0078, V0080) of the white dash (1 Mbit/s).
Old version of the ECU firmware loads the CAN-Bus at 100% with data for the cluster,
so HW-Filtering would be a big improvement! Do a "t4e.py -o ifp", if it's success,
you will leave the ECU firmware and jump into the flasher program, which doesn't
overload the CAN-Bus, then make the download with "flasher.py -o dl -b 0 1 2".

[Python 3]: https://www.python.org/download/releases/3.0/
[python-can]: https://python-can.readthedocs.io/en/master/installation.html
[CAN-BUS adapter]: https://python-can.readthedocs.io/en/master/interfaces.html
[patch]: https://github.com/craigpeacock/mcp251x

## Files

 Files                 | Description
 ----------------------|------------
 t4e.py                | Program to talk to the original UNLOCKED Software (Read/Write RAM)
 flasher.py            | Program to talk to the flasher Software (Read/Write RAM+Flash+EEPROM)
 flasher/*.bin         | CAN-Bus Flasher for the MPC563
 gui.py                | Graphical interface for both t4e.py and flasher.py
 sign.py               | Tool for CRC
 bdm-pi.py             | MPC5xx BDM Bit-Banging Tool for the Raspberry Pi (Debugger Base)
 bin2crp.py            | Convert a BIN into a CRP file (post 2008).
 t4e-black.py          | Tool to upload a CRP file to a locked black ECU (Write Flash).
 t4-white.py           | Tool to upload a CRP file to a locked white ECU (Write Flash).

## Command line example (OBD Port, unlocked ECU)

	1. sudo ip link set can0 up type can bitrate 1000000
	2. ./t4y.py -o dl -z 0 1 2 3 4
	3. ./t4y.py -o v -z 0 1 2
	4. cp calrom.bin calrom.ori.bin
	5. [Modify calrom.bin with RomRaider]
	6. ./sign.py sign_calrom calrom.ori.bin calrom.bin calrom.bin "MYTUNE"
	7. ./t4e.py -o ifp
	8. ./flasher.py -o vfp
	9. ./flasher.py -o e -b 1
	10. ./flasher.py -o vb -b 1
	12. ./flasher.py -o p -b 1
	13. ./flasher.py -o v -b 1
	14. ./flasher.py -o r

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
	5. ./flasher.py -o b &
	6. ./bdm-pi.py -o sfp
	7. ./flasher.py -o dl -b 0 1 2
	8. ./flasher.py -o c -b 0 1 2

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
	2. ./sign.py check_crc_black_calrom calrom_original.bin
	3. [Modify calrom.bin with RomRaider]
	4. ./sign.py unlock_black_calrom calrom_original.bin calrom.bin
	5. ./bin2crp.py calrom calrom.bin calrom.crp
	6. ./t4e-black.py -f calrom.crp *** [TESTED only 1x BE CAREFUL] ***
	7. [TURN CAR ON]
	8. ./t4e.py -s black -o dl -z 0 2 3 4
	9. ./t4e.py -s black -o v -z 0 2

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

## Live tuning.

It's possible to make modifications on running engine for test, because the
maps are copied into the RAM.

It would need another software for that, which will use t4e.py as library to
access RAM.

## Safe Usage

You really need to understand how this work to be able to use the flasher
(flasher.py) safely.

 1. The RAM will be lost at power cut off or reset.
 2. The flasher needs to be installed in RAM.
 3. To install the flasher in the RAM, the Main Program is needed.
 4. To start the Main Program, a Bootloader is needed.

So if you erase the Main Program and cut the power off, don't expect to be able
to restore your ECU with the "t4e.py" script. You will have to save your ECU with
the programming (BDM) port on the board or with the "t4e-black.py" script.

Use the verify function before resetting the ECU! If your programming a Bootloader
or a Main Program, be sure that the files are good and valid.

*Note: The Main Program seems to be OK without Calibration.*

## GUI

The simple GUI... not all options are implemented...

![alt text](documentation/Usage/GUI.png "GUI Demo")

## RomRaider

You have to open the "calrom.bin" file of your dump.

![alt text](documentation/Usage/RomRaider.png "Tune Demo")

## Debugging the MPC 5xx

With a small effort, the "bdm-pi.py" script could implements breakpoint, continue
und read/write registers functionality.

