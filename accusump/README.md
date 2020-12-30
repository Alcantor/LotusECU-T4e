## Introduction

***NOT TESTED ON CAR YET***

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

	1. Replace the original oil pressure switch with an analog one.
	2. Connect the accusump selenoid on the ACIS Airbox Flap connector.

The original oil pressure switch only have one wire for the signal. Analog
oil pressure sensor often needs a GND and a 5 Volts wires, the 5 Volts could be
from your separate gauge, or from another sensors (MAP, TPS or MAF).

***DO NOT USE 12V***

## Hardware Specifications

	- The selenoid of the accusump needs 600 mA.
	- The selenoid driver (L9822E) of the T4e can provide 750 mA continuously and 1050 mA for high inrush currents.
	- The selenoid driver (L9822E) has a short circuit protection.
	- The [Depo-Racing 4in1 gauge] use a 0-5 Volts max 10 bar oil pressure sensor (3 pins Delphi plug).
	- The standard oil pressure switch has a threshold at ???.

[Depo-Racing 4in1 gauge]:https://www.elise-shop.com/high-precision-60mm-boost-oiltemp-oil-pressure-gauge-p-502177.html

## Formula

For common 10 bar oil pressure sensor.

	- Oil pressure sensor formula: p = 2.59 * U - 1.295 (p: bar, U: Volts)
	- ADC 11 Bits: U = 5/1024 * SAMPLE
	- 11 Bits Sample to Pressure in bar: p = 0.012646484 * s - 1.295
	-  8 Bits Sample to Pressure in bar: p = 0.050585938 * s - 1.295
	- Pressure in bar to 11 Bits Sample: s = (p + 1.295) / 0.012646484
	- Pressure in bar to  8 Bits Sample: s = (p + 1.295) / 0.050585938

## Teaser

![alt text](https://github.com/Alcantor/LotusECU-T4e/raw/master/documentation/Usage/accusump/table.png "Accusump in RomRaider")

