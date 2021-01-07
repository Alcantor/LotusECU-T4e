# Lotus T4e Flasher

## Disclaimer

***Use it at your own RISK.***

## Introduction

This is my attempt to tune my Lotus Exige S2 (T4e ECU White Dash).

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

My final goal was to control my accusump with the T4e ECU, that was not possible
without patching the main program. See folder [accusump].

To be able to patch the main program more safely I've includer the flasher into
the bootloader. See folder [stage15].

[accusump]:https://github.com/Alcantor/LotusECU-T4e/tree/master/accusump
[stage15]:https://github.com/Alcantor/LotusECU-T4e/tree/master/stage15

## Licensing

Under [CC-NC-SA].

[CC-NC-SA]: https://creativecommons.org/licenses/by-nc-sa/4.0/

## Original Method

I'am not sure how "others" are doing the flashing. After reading some posts of
Cybernet, I'have the feeling that the Bootloader on White Dash cars can do some
loading/flashing trough K-Line. I didn't take the time to disassemble the
bootloader yet.

And from BOE FastWorks Software:
> The initial flash takes a while since it rewriting the firmware in the ECU.
> This one took me maybe 5-10 minutes total. In which you are turning the ignition on and off.
> Once you get passed that one, writing a "tune" only takes about 20 seconds.

Hum, turning on/off the car and so long... They are probably patching the bootloader
trough K-Line. Once patched, it will go quicker because they are using the CAN-Bus.

Anyway I am doing it through CAN-Bus only, leaving the bootloader as is. In
contrario I'am using a little hack which is not guaranteed to work on all
software versions of the ECU.

## Prerequisite

The [Python 3] interpreter with the [python-can] module and a compatible [CAN-BUS adapter].

[Python 3]: https://www.python.org/download/releases/3.0/
[python-can]: https://python-can.readthedocs.io/en/master/installation.html
[CAN-BUS adapter]: https://python-can.readthedocs.io/en/master/interfaces.html

## Files

 Files                 | Description
 ----------------------|------------
 t4e.py                | Program to talk to the original Software (Read/Write RAM)
 flasher.py            | Program to talk to the flasher Software (Read/Write RAM+Flash)
 flasher/*.bin         | CAN-Bus Flasher for the MPC563
 gui.py                | Graphical interface for both t4e.py and flasher.py
 sign.py               | Tool for CRC

## Command line example

    0. sudo ip link set can0 up type can bitrate 1000000
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

    To 0: Turn CAN-Bus on [Linux/SocketCAN Only]
    To 1: Download the ECU like cybernet does.
    To 2: Backup, backup, backup...
    To 3: Tune your engine!
    To 4: Install the flasher into the RAM. *
    To 5: Verify the flasher itself.
    To 6: Erase the calibration block. *** [TESTED] ***
    To 7: Verify the erasure.
    To 8: Program the calibration block. *** [TESTED] ***
    To 9: Verify the calibration block.
    To 10: Reset.

*: This use a little hack (Stack Overwrite) to gain control, retry 4-5 times if it fails.

*: Tested with "BCroftT4E070 01/11/2005 Lotus EngV0078", "BCroftT4E090 14/07/2006 Lotus EngV0091" and "BCroftT4E090 14/07/2006 Lotus EngV0093" yet.

## Live tuning.

It's possible to make modifications on running engine for test, because the
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

The simple GUI...

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/GUI.png "GUI Demo")

## RomRaider

You have to open the "calrom.bin" file of your dump.

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/RomRaider.png "Tune Demo")

