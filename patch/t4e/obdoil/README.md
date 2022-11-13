## Introduction

An attempt to add oil pressure and oil temperature for the OBD interface.

*** Only tested on bench. ***

## Hardware

 1. Replace the original oil pressure switch with an analog one (PIN RA2).
 2. Add an oil temperature sensor on the PIN LC3.

***Note***: The oil pressure input is calibrated for a 3 wires and 0-10 bar
sensor.

***Note***: The oil temperature input is calibrated like the coolant temperature.
And thus limited to 120 °C.

## Queries

 - Oil Pressure: OBD mode 0x01 pid 0x23 (Fuel Pressure)
 - Oil Temperature: OBD mode 0x01 pid 0x5C

