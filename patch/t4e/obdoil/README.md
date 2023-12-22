## Introduction

An attempt to add oil pressure and oil temperature for the OBD interface.

*** Only tested on bench. ***

## Hardware

 1. Add an oil pressure sensor on the PIN LE4.
 2. Add an oil temperature sensor on the PIN LD3.

![alt text](../../../documentation/Usage/obdoil/oncar.jpg "Mounted on the car")

***Note***: The oil pressure input is calibrated for a 3 wires and 0-10 bar
sensor.

***Note***: The oil temperature input is calibrated for a NTC 53k (at 25°C) and Beta 3940.
The temperature encoding is the same as the water temp and thus limited to 120 °C.

## Queries

 - Oil Pressure: OBD mode 0x01 pid 0x23 (Fuel Pressure)
 - Oil Temperature: OBD mode 0x01 pid 0x5C
