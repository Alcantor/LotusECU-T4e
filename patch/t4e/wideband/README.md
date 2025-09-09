## Introduction

This is to replace the Pre-O2 sensor with a Wideband O2.

The AFR will be available on OBD interface but internally the ECU will
transform the wideband signal into a narrow signal and it will continue
to work as if the Pre-O2 would be a narrow one.

## Calibration

The Spartan controller outputs 1.66 V during the first 5 seconds and then 3.33 V
for the next 5 seconds for calibration purposes. This patch uses this feature to
determine whether the wideband or narrowband sensor is connected. Correction is
then applied if the approximate voltages (± 0.5 V) are detected.

## Limitation

The input of the original O2 sensor has a 332 ohm pull-down resistor (and a
3.16 kohm pull-up).

This limits the reading to approximatively 18 AFR instead of 20 AFR.

## Hardware

 1. 14point7 Spartan 2 wideband controller.
 2. Kostal 09 3414 01 plug.

***Note***: The heater ground will be turned on only when the engine is started.

***Note***: The Spartan 3 is not compatible (without modification) because the
heater ground is required during startup.

## Queries

 - Lambda     : OBD mode 0x01 pid 0x24
 - Correction : OBD mode 0x22 pid 0x0403 (AB: Slope 1/4096, CD: Offset 5/1023v)

## Pictures

![alt text](../../../documentation/Usage/wideband/spartan2.jpg "Spartan 2 Wideband Controller")
![alt text](../../../documentation/Usage/wideband/oncar.jpg "Mounted on the car")
![alt text](../../../documentation/Usage/wideband/obdapp.jpg "Result in a OBD Application")
