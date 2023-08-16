## Introduction

To edit the "calrom.bin" files in RomRaider a definition file is required.

It's also possible to open the "decram.bin" file to show some learned data.

The T4e RomRaider definition is very complete and avalaible for free. For the
T6 definition please contact me.

## Files

 Files                            | Description
 ---------------------------------|------------
 A129E0002-Ghidra-Disassembly.gar | Disassembly of a Lotus Exige 2008 T4e ECU.
 CD0MB009-Ghidra-Disassembly.gar  | Disassembly of a Caterham Seven T6 ECU.
 G120E0163-Ghidra-Disassembly.gar | Disassembly of a Lotus Elise 2012 T6 ECU.
 symbols_T4e.csv                  | Symbols exported from Ghidra for the T4e ECU.
 symbols_T6caterham.csv           | Symbols exported from Ghidra for the T6 Caterham ECU.
 symbols_T6lotusL4.csv            | Symbols exported from Ghidra for the T6 Lotus L4 ECU.
 make_defs.py                     | Transform "*.csv" into "*_defs.xml".
 T4e_defs.xml                     | T4e RomRaider definition.
 T6caterham_defs.xml              | T6 Caterham RomRaider definition.
 T6lotusL4_defs.xml               | T6 Lotus Elise RomRaider definition.

## Opening *.CPT files

Original calibration files does not contain any "free space" at the end. So the
file size is not 64kb.

Use the calibration tool to resize the file to the appropriate size.

## Usage

The "T4e_defs.xml" was made for a 2008 T4e ECU. It should also work for 2006-2007
ECUs but some errors may appear.

Read the description of the tables:

![Description](../documentation/Usage/RomRaider2.png)

## The Caterham T6

The T6 ECU on the Caterham have the same hardware but the software is slightly
modified.

The Caterham use Speed Density computation instead of a MAF sensor, so they took
the Lotus Elise Software and modified the load computation to reflect that.
