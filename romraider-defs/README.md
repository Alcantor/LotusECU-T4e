## Introduction

To edit the "calrom.bin" files in RomRaider a definition file is required.

It's also possible to open the "decram.bin" file to show some learned data.

## Files

 Files                            | Description
 ---------------------------------|------------
 A129E0002-Ghidra-Disassembly.gar | Disassembly of a 2008 ECU.
 symbols.csv                      | CAL_ Symbols exported from Ghidra.
 make_T4e_defs.py                 | Transform "*.csv" into "T4e_defs.xml".
 T4e_defs.xml                     | RomRaider definition.
 T4_defs_plust4e.xml              | Definition file from Obeisance adapted for the T4e.

## Opening *.CPT files

Original calibration files does not contain any "free space" at the end. So the
file size is not 64kb.

RomRaider does not open the file correctly unless you manually change the size
in the XML definition. So replace the "64kb" by the appropriate size, for example
"15540b".

## Usage

The "T4e_defs.xml" was made for a 2008 T4e ECU. It should also work for 2006-2007
ECUs but some errors may appear.

Read the description of the tables:

![Description](../documentation/Usage/RomRaider2.png)
