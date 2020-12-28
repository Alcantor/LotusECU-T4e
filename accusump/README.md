## Introduction

***DO NOT USE, NEVER TESTED***

I've have an accusump, and like [Apex_in_sno], I wanted a way to have the sump
on line all the time, but not have it drain when the motor is idling and I wanted
a full charge for startup.

[Apex_in_sno]: https://www.lotustalk.com/threads/my-sick-accusump-install.122280/

Then I figured out that I could use the ACIS Airbox Flap output of the ECU to
control my accusump.

## Files

	build.py: Build the file "prog.bin" and "calrom.bin"
	prog.bin: Patched program from ALS3M0244F with the accusump control in it.
	calrom.bin: Patched calibration from A128E6009F with the accusump table in it.
	T4_defs_plust4e.patch: Patch for the XML-Definition to edit the table in RomRaider.

## Hardware

	1. Replace the original oil pressure switch with an analog one* (***MAX 5 Volt input!!!***)
	2. Connect the accusump selenoid on the ACIS Airbox Flap connector.

*: 0-5V -> 0-10 Bar ***NEVER TESTED YET***

## Teaser

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/accusump.png "Accusump in RomRaider")..

