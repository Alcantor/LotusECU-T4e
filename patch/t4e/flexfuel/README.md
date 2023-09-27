## Introduction

An attempt to add a flexfuel sensor.

## Hardware

 1. Add a Continental flexfuel sensor on the PIN LG1.
 2. Use SAE-Quick-Connect 5/16" (8 mm) on the Lotus.
 3. Use SAE-Quick-Connect 3/8" (9.5 mm) on the sensor.

The PIN LG1 is the only input which can sample a PWM signal. It's a 5V input,
but the sensor has a open-drain output, so even if it's powered by 12V, it's ok.

## Queries

There is no standard for the fuel temperature, so I'am using the ambiant air
temperature PID instead.

 - Fuel temperature    : OBD mode 0x01 pid 0x46
 - Ethanol content (%) : OBD mode 0x01 pid 0x52
