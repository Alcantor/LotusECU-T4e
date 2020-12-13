# Lotus T4e Flasher

## Disclaimer

***Use it at your own RISK.***

## Introduction

This is my attempt to tune my Lotus Exige S2.

It's heaveliy based on the work of [Obeisance] and [Cybernet].

[Obeisance]: https://www.lotustalk.com/threads/daft-disassembly.352193/
[Cybernet]: https://www.lotustalk.com/threads/t4e-ecu-editor-preview.372258/

I didn't have a Arduino with a CAN-Shield but I have an USB-to-CAN Adapter.
So I made my own Python-Script (Linux Only) to make the dump. It sould also work
with a RaspberryPi and a CAN-Shield (SocketCAN Driver).

After that I've realized that the Calibration ROM located at 0x10000 looks like
identical to the T4 ECU at address 0x70000. So I've edited the XML to use the
new offset.

But how to upload the modification back? Hum, after somes hours of disassembling,
I've figured out how to write to the RAM but not to the Flash.

Well If I can write to the RAM, I'am allowed to upload my own program. That's
what I've done. So I've write a small CAN-Bus Flasher to write to the Flash
trough the OBD Port.

## Files

	t4e.py: Program to talk to the original Software (Read/Write RAM)
	flasher.py: Program to talk to the flasher Software (Read/Write RAM+Flash)
	injection/flasher.bin: CAN-Bus Flasher for the MPC563
	gui.py: Graphical interface for both t4e.py and flasher.py

## Command line example

	1. ./t4y.py -o dl -z 0 1 2 3 4
	2. cp calrom.bin calrom.ori.bin
	3. [Modify calrom.bin with RomRaider]
	4. ./t4e.py -o ifp
	5. ./flasher.py -o vfp
	6. ./flasher.py -o e -b 1
	7. ./flasher.py -o p -b 1
	8. ./flasher.py -o v -b 1
	9. ./flasher.py -o r

	To 1: Download the ECU like cybernet does.
	To 2: Backup, backup, backup...
	To 3: Tune your engine!
	To 4: Install the flasher into the RAM *
	To 5: Verify the flasher itself.
	To 6: Erase the calibration block *** [TESTED] ***
	To 7: Program the calibration block *** [QUIRK: Need 3-4 Cycles to work] ***
	To 8: Verify the calibration block
	To 9: Reset

*: This use a little hack (Stack Overwrite) to gain control, retry 4-5 times if it fails.

*: Tested with "BCroftT4E070 01/11/2005 Lotus EngV0078" and "BCroftT4E090 14/07/2006 Lotus EngV0093" yet.

## Live tuning.

It's possible to make modifications on running engine for test, because some
maps are copied into the RAM.

It would need another software for that, which will use t4e.py as library to
access RAM.

## GUI

Your could install the software into a Raspberry PI and access the GUI with
a web browser.

For that use "startweb.sh" script.

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/GUI.png "GUI Demo")

