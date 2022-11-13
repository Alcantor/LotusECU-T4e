## Introduction

I have an accusump, and like [Apex_in_sno], I wanted a way to have the sump
on line all the time, but not have it drain when the motor is idling and I wanted
a full charge for startup.

[Apex_in_sno]: https://www.lotustalk.com/threads/my-sick-accusump-install.122280/

Then I figured out that I could use the ACIS Airbox Flap output of the ECU to
control my accusump.

## Files

 Files                 | Description
 ----------------------|------------
 build.py              | Build the file "prog.bin" and "calrom.bin".
 prog.bin              | Patched program from A128E6009F with the accusump control in it.
 calrom.bin            | Patched calibration from A128E6009F with the accusump table in it.
 T4_defs_plust4e.patch | Patch for the XML-Definition to edit the table in RomRaider.

***The .bin files are only for my car. You need to build your own files!***

## Hardware

 1. Replace the original oil pressure switch with an analog one.
 2. Place a new relay (SPST NO).
 3. Connect the coil of the relay to the ACIS Airbox Flap connector (2 pins Sumitomo plug).
 4. Connect the accusump selenoid to the relay output.

The original oil pressure switch only have one wire for the signal. Analog
oil pressure sensor often needs a GND and a 5 Volts wires, the 5 Volts could be
from your separate gauge, or from another sensors (MAP, TPS or MAF).

***DO NOT USE 12V***

## Hardware Specifications

 - The selenoid of the accusump needs 600 mA to hold the valve opened.
 - The selenoid of the accusump has a too big inrush current for the driver (L9822E).
 - The selenoid driver (L9822E) of the T4e can provide 750 mA continuously and 1050 mA for high inrush currents.
 - The selenoid driver (L9822E) has a short circuit protection.
 - The [Depo Racing 4in1 gauge] use a 0-5 Volts max 10 bar oil pressure sensor (3 pins Delphi plug).
 - The standard oil pressure switch has a threshold at 0.2 bar.

[Depo Racing 4in1 gauge]: https://www.elise-shop.com/high-precision-60mm-boost-oiltemp-oil-pressure-gauge-p-502177.html

***It's not possible to connect directly the ACIS output to the accusump. A relay is needed.***

## Formula

For common 10 bar oil pressure sensor (0bar=0.5V and 10bar=4.5V).

 - Oil pressure sensor formula: p = (U - 0.5) * 2.5 = 2.5 * U - 1.25 (p: bar, U: Volts)
 - ADC 10 Bits: U = 5/1024 * s
 - 10 Bits Sample to Pressure in bar: p = 0.012207031 * s - 1.25
 -  8 Bits Sample to Pressure in bar: p = 0.048828125 * s - 1.25
 - Pressure in bar to 10 Bits Sample: s = (p + 1.25) / 0.012207031
 - Pressure in bar to  8 Bits Sample: s = (p + 1.25) / 0.048828125

## Teaser

![alt text](../../../documentation/Usage/accusump/table.png "Accusump in RomRaider")

