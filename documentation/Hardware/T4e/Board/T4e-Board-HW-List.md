## T4e Top

Part         | Description
-------------|------------
SC33394FDH   | Switch Mode Power Supply with Multiple Linear Regulators and High Speed CAN Transceiver
LM2904       | Dual Operational Amplifier
MPX4001A     | Integrated Silicon Pressure Sensor
MC68HC908JK8 | Microcontroller 8 bits
1NV04        | Fully autoprotected Power MOSFET
L9822EPD     | Octal serial solenoid driver
TLE6220GP    | Smart Quad Low-Side Switch
LM2903       | Dual Comparators
VP251        | Industrial CAN Transceiver
L9119D       |
SM5A27       | Transient Voltage Suppressors
76407D       | Power MOSFET
TLE6209R     | H-Bridge for DC-Motor
MAAC V358    |
25160AN      | SPI Serial EEPROM
L9613        | Data interface (K-Line)
LM6152BCM    | Dual and Quad 75 MHz GBW Rail-to-Rail I/O Operational Amplifiers
27M2C        | Dual Operational Amplifier

## T4e Bottom

Part         | Description
-------------|------------
MPC563MZP56  | Microcontroller 32 bits PowerPC
4.00 MHz     | Quatz for MPC

## MPC563 Memory Map

Offset   | Size    | Description
---------|---------|------------
0x000000 | 0x04000 | Bootloader stage 1
0x004000 | 0x0C000 | Bootloader stage 2 (CRC at 0xFFFE)
0x010000 | 0x10000 | Calibration (Maps)
0x020000 | 0x60000 | Program
0x2F8000 | 0x00800 | 2 KByte DecRAM - ECU Correction Values (Copy of SPI EEPROM)
0x3F8000 | 0x08000 | 32 KByte CalRAM - Main RAM
