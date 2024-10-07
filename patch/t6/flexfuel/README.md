## Introduction

This patch allows the addition of flex-fuel capability to the T6 OEM ECU.

Only OBD, no ethanol tables yet.

## Hardware

Continental flexfuel sensor on the PIN RG4.

## Queries

There is no standard for the fuel temperature, so I'am using the ambiant air
temperature PID instead.

 - Fuel temperature    : OBD mode 0x01 pid 0x46
 - Ethanol content (%) : OBD mode 0x01 pid 0x52

