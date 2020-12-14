# Lotus T4e Flasher

## Disclaimer

***Use it at your own RISK.***

## Introduction

This is my attempt to tune my Lotus Exige S2.

It's heaveliy based on the work of [Obeisance] and [Cybernet].

[Obeisance]: https://www.lotustalk.com/threads/daft-disassembly.352193/
[Cybernet]: https://www.lotustalk.com/threads/t4e-ecu-editor-preview.372258/

I didn't have a Arduino with a CAN-Shield but I have an USB-to-CAN Adapter.
So I made my own Python-Script (Linux and Windows) to make the dump. It sould also work
with a RaspberryPi and a CAN-Shield (SocketCAN Driver).

After that I've realized that the Calibration ROM located at 0x10000 looks like
identical to the T4 ECU at address 0x70000. So I've edited the XML to use the
new offset.

But how to upload the modification back? Hum, after somes hours of disassembling,
I've figured out how to write to the RAM but not to the Flash.

Well If I can write to the RAM, I'am allowed to upload my own program. That's
what I've done. So I've write a small CAN-Bus Flasher to write to the Flash
through the OBD Port.

## Original Method

I'am not sure how "others" are doing the flashing. After reading some posts of
Cybernet, I'have the feeling that an encrypted Bootloader can do the flashing
through K-Line. Can someone confirm me this? I didn't take the time to disassemble
the bootloader yet.

Anyway I am doing it through CAN-Bus.

## Prerequisite

	- [Python3][python3]
	- [python-can][python-can] module
	- A compatible [CAN-BUS adapter][adapter]

[python3]: https://www.python.org/download/releases/3.0/
[python-can]: https://python-can.readthedocs.io/en/master/installation.html
[adapter]: https://python-can.readthedocs.io/en/master/interfaces.html

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
	7. ./flasher.py -o vb -b 1
	8. ./flasher.py -o p -b 1
	9. ./flasher.py -o v -b 1
	10. ./flasher.py -o r

	To 1: Download the ECU like cybernet does.
	To 2: Backup, backup, backup...
	To 3: Tune your engine!
	To 4: Install the flasher into the RAM. *
	To 5: Verify the flasher itself.
	To 6: Erase the calibration block. *** [TESTED] ***
	To 7: Verify the erasure.
	To 8: Program the calibration block. *** [UNTESTED] ***
	To 9: Verify the calibration block.
	To 10: Reset.

*: This use a little hack (Stack Overwrite) to gain control, retry 4-5 times if it fails.

*: Tested with "BCroftT4E070 01/11/2005 Lotus EngV0078" and "BCroftT4E090 14/07/2006 Lotus EngV0093" yet.

## Live tuning.

It's possible to make modifications on running engine for test, because some
maps are copied into the RAM.

It would need another software for that, which will use t4e.py as library to
access RAM.

## Safe Usage

Your really need to understand how this work to be able to use the flasher
(flasher.py) safely.

	1. The RAM will be lost at power cut off or reset.
	2. The flasher needs to be installed in RAM.
	3. To install the flasher in the RAM, the Main Program is needed.
	4. To start the Main Program, a Bootloader is needed.

So if you erase the Main Program and cut the power off, don't expect to be able
to restore your ECU with that program.

Use the verify function before resetting the ECU! If your programming a Bootloader
or a Main Program, be sure that the files are good and valid.

*Note: The Main Program seems to be OK without Calibration.*

## GUI

Your could install the software into a Raspberry PI and access the GUI with
a web browser.

For that use "startweb.sh" script.

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/GUI.png "GUI Demo")

