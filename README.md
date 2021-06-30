# Lotus T4/T4e Flasher

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

After that I went a little further by looking at the ECU Black Dash and the T4.

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

Destination addresses are NOT verified, so it's possible to write a program to
the RAM and take the control by poisoning the stack. So reading is indirectly
possible.

### Post 2008

The T4e of the black dashboard cars has another bootloader which does the
reprogramming with CAN-Bus (500 kbit/s).

This bootloader accepts an encrypted .CRP file and can update the calibration,
the software or the EEPROM. Only writing with CAN-Bus, no reading...

Destination addresses are verified. So there is no possibilities to write the
RAM.

### CRP Files

ECU Updates from Lotus are .CRP files. Somes are available on the [VCIS].
Most of them are included in the Lotus TechCentre or Lotus Scan 3.

The structure of the .CRP files has completely change in 2008.

[VCIS]: https://vsic.lotuscars.com/

## Live tuning access [2005-2008]

For most of the white dashboard, there is an access provided by the main program
trough CAN-BUS (1 Mbit/s). It's intended for "live tuning" and not for
reprogramming the ECU, but with somes hacks it could be use for this purpose.

This access has been definitively locked on the black dashboard. But it's
possible to re-enable it, with a BDM access or a modified .CRP file.

My little hack is not guaranteed to work on all software versions of the
ECU but when it works it's very reliable (A good CAN-Bus adapter is mandatory).

## Prerequisite

The [Python 3] interpreter with the [python-can] module and a compatible [CAN-BUS adapter].

The [Macchina P1] is my actual recommendation if you want to buy hardware, but I
have not tested it my-self yet.

The CANable (with slcan firmware) is very simple to use, but it has a bottleneck
with the serial interface, and does not work well with the "ltacc.py" script.
In contrario the "flasher.py" works flawless (but slowly) with this adapter
because it doesn't make bulk read/write. So if you still want to use this adapter,
use the download function of the "flasher.py" and not from the "ltacc.py".

The CANable (with CandleLight firmware) is great but unsupported under Windows yet.
This could change in a near future (see develop of python-can).

The IXXAT USB-to-CAN Adapter is easy to use and reliable but expensive.

The Raspberry-Pi + CAN-Hat is cheap and you can use it as a BDM-Programmer, but
it's not really reliable. The MCP2515 has only two receive buffers and the linux
driver for it doesn't implement HW-Filtering ([patch] ?). This leads to packet
loss, especially for old versions (Like V0078, V0080) of the white dash (1 Mbit/s).
Old version of the ECU firmware loads the CAN-Bus at 100% with data for the cluster,
so HW-Filtering would be a big improvement!

[Python 3]: https://www.python.org/download/releases/3.0/
[python-can]: https://python-can.readthedocs.io/en/master/installation.html
[CAN-BUS adapter]: https://python-can.readthedocs.io/en/master/interfaces.html
[Macchina P1]: https://www.macchina.cc/catalog/p1-boards/p1-under-dash
[patch]: https://github.com/craigpeacock/mcp251x

## GUI

![alt text](documentation/Usage/GUI.png "GUI")

[Command line examples] are in the documentation folder.

[Command line examples]: documentation/Usage/cmd-examples.md

## RomRaider

You have to open the "calrom.bin" file of your dump.

![alt text](documentation/Usage/RomRaider.png "Tune Demo")

## Live tuning.

It's possible to make modifications on running engine for test, because the
maps are copied into the RAM.

It would need another software for that, which will use "ltacc.py" as library to
access RAM of unlocked ECU.

## Safe Usage

You really need to understand that the memory of the ECU is splitted into 3
parts: The bootloader, the calibration and the program.

If the bootloader is erased, you will have no other choice than open the ECU to
flash it again.

The "live tuning" access is provided by the main program. So if use this access
to flash the ECU, think twice before erasing the program.

The ECU seems fine to boot without a valid calibration, so erasing this part is
quite safe. Of course the car won't run in this case.

