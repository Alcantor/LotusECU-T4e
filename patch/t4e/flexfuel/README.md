## Introduction

An attempt to add a flexfuel sensor.

*** Only OBD. No fuel blending yet!!! ***

## Hardware

 1. Add a continental flexfuel sensor on the PIN LG1.

The PIN LG1 is the only input which can sample a PWM signal. It's a 5V input,
but the sensor has a open-drain output, so even if it's powered by 12V, it's ok.

## Queries

 - Ethanol fuel % : OBD mode 0x01 pid 0x52

