# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This directory contains reverse-engineered code of a Lotus ECU.

### OBD Communication

The T4e ECU supports both K-Line and CAN-Bus for OBD diagnostics. Since 2008, CAN-Bus is the primary interface.

### Key Files

- `black91.c` - Exported C code from Ghidra of the Lotus T4e 2008 ECU (black cluster version 91)
- `boot08.c` - Exported C code from Ghidra of the Lotus T4e 2008 ECU (crp08 updater)
- `hc08.c` - Exported C code from Ghidra of the Lotus T4e 2008 ECU (HC08 Safety CPU)
- `guide/dot/*.dot` - Graphviz DOT files that visualize ECU formula calculations
- `guide/T4E090_guide.tex` - Detailed description of ECU functions (LaTeX guide)

## Naming Conventions

Names use lowercase with underscores, organized from general category to specific detail (e.g., `ign_adv_base`).

Prefixes pairs (`_disable`/`_enable`, `_low`/`_high`, `_limit_l`/`_limit_h`) should be kept at the end
as much as possible, so an export script can merge them if desired.

### Symbol Prefixes

| Prefix | Purpose | Notes |
|--------|---------|-------|
| `ac_` | Air conditioning | |
| `CAL_` | Calibration data | Exported to RomRaider definitions. Format: `CAL_category_name`. Underscores become spaces. **EOL comments are used as table descriptions.** In formulas, the current calibration value is CAPITALIZED (e.g., `stft = stft + STEP * adj`). |
| `closedloop_` | Closed-loop fuel control | Shared state spanning both STFT and LTFT (e.g. `closedloop_flags`). Use `stft_` or `ltft_` for STFT/LTFT-specific symbols. |
| `ltft_` | Long-term fuel trim | LTFT correction zones (zone1=idle, zone2=low load, zone3=high load) and conditions |
| `stft_` | Short-term fuel trim | STFT O2 feedback, parameters, and enabling conditions |
| `COD_` | Coding data | Vehicle options (T6 ECU only) |
| `DAT_` | Unnamed Ghidra data | Needs renaming during reverse engineering |
| `dev_` | Development/tuning variables | Writable via OBD for real-time tuning |
| `ecu_` | ECU system parameters | Unlock, start relay, VIN, generic ECU config |
| `evap_` | Evaporative emissions control system | |
| `fan_` | Cooling fan control | |
| `hc08_` | MC68HC908JK8 safety processor | Monitors PPS/TPS relationship |
| `idle_` | Idle control system | |
| `ign_` | Ignition | |
| `init_` | Initialization functions | Called once at startup |
| `inj_` | Injection | |
| `injtip_` | Transient fueling | Tip-in/tip-out enrichment |
| `isr_` | Interrupt service routines | TPU and hardware interrupts |
| `knock_` | Knock detection | |
| `LEA_` | Learned parameters | ECU adaptive corrections. Creates definitions for `decram.bin` visualization. |
| `load_` | Air mass per intake stroke | |
| `misc_` | Miscellaneous | Items that don't fit other prefixes |
| `misfire_` | Misfire detection | Stroke-time based; feeds OBD P030x DTCs and catalyst damage protection |
| `o2_` | Oxygen sensor (lambda sensor) | |
| `obd_` | OBD diagnostics | DTCs, freeze frames, monitors, IUMPR |
| `pps_` | Pedal position sensor | Dual sensors: `_1`, `_2` suffixes |
| `REG_` | Microcontroller registers | Hardware register access |
| `sensor_` | Values from various sensors | |
| `sensor_adc_` | Voltage sensor values | |
| `tc_` | Traction control | |
| `tpms_` | Tire Pressure Monitoring System | CAN communication with TPMS module |
| `tps_` | Throttle position sensor | Dual sensors: `_1`, `_2` suffixes |
| `vvl_` | Variable Valve Lift | High-lift cam engagement |
| `vvt_` | Variable Valve Timing | |

All `CAL_` and `LEA_` symbols must use types supported by: `../ghidra_scripts/ExportRomRaiderDefs.java`

### Suffixes

| Suffix | Meaning |
|--------|---------|
| `_1`, `_2` | General numbering (e.g., `pps_1`, `tps_2`) |
| `_5ms` | Called every 5ms |
| `_10ms` | Called every 10ms |
| `_100ms` | Called every 100ms |
| `_adj` | Adjustment, can be a factor or an offset |
| `_age` | Number of samples back in a history buffer for rate-of-change (dt) calculation |
| `_avg` | Arithmetic average (sum / count). Typically accompanied by `_sum` and `_count`. Use `_smooth` for low-pass filters |
| `_base` | Base value before adjustments are applied |
| `_count` | Counter variable used for event |
| `_ctrl_d` | PID controller derivative term |
| `_ctrl_i` | PID controller integral term accumulator |
| `_ctrl_p` | PID controller proportional term |
| `_dec` | Decrement value |
| `_delay` | Fixed waiting duration before an action or condition is allowed to proceed |
| `_diff` | Difference |
| `_disable` | Threshold to deactivate a feature (hysteresis pair with `_enable`) |
| `_dt` | Rate of change (differential over time) |
| `_enable` | Threshold to activate a feature (hysteresis pair with `_disable`) |
| `_fallback` | Fixed value substituted for a sensor reading when that sensor is confirmed faulted |
| `_flags` | Bit flags |
| `_gain` | Controller or scaling gain factor (sometimes paired with `_offset`) |
| `_high` | Upper bound of a range pair (e.g., `tps_1_range_high`) |
| `_history` | Usually array of older values of a variable |
| `_i` | Index (Likely to be use in a array) |
| `_inc` | Increment value |
| `_limit` | Combined low and high limit |
| `_low` | Lower bound of a range pair (e.g., `tps_1_range_low`) |
| `_limit_h` | High limit (clamps value) |
| `_limit_l` | Low limit (clamps value) |
| `_margin` | Offset from a reference value used as a threshold or hysteresis band |
| `_max` | Observed maximum value. Note: `CAL_*_max` are thresholds |
| `_min` | Observed minimum value. Note: `CAL_*_min` are thresholds |
| `_adv` | Advance angle (used for `ign_` and `vvt_`) |
| `_retard1` | Knock spark advance retard (Lotus terminology) |
| `_retard2` | Octane scaler (Lotus terminology) |
| `_smooth` | Variable that has been through a low pass filter |
| `_smooth_x` | Low-pass filter accumulator storing scaled value. Divide by the scale to get `_smooth` |
| `_state` | State machine current state |
| `_step` | Increment/Decrement value (same in both direction) |
| `_stop` | Qualifier: value applies when engine is stopped (e.g., `_stop_coolant` = coolant temp at engine-off) |
| `_sum` | Running total accumulated over time (e.g., PID integral accumulator summing error samples) |
| `_target` | Setpoint/desired value |
| `_threshold` | Decision point that triggers an action (not a clamp; see `_limit`) |
| `_time_between_step` | Time/count between recovery or adjustment steps |
| `_timer` | Variable used for timing |
| `_offset` | Zero-point calibration value subtracted before scaling (paired with `_gain`) |
| `_period` | PWM carrier period in timer ticks |
| `_reactivity` | Reactivity/responsiveness parameter, often used for smoothing |

## RomRaider Definitions

Definition files for RomRaider are in `../`. The definition file enables editing calibration maps in `calrom.bin`.

## T4e Architecture

### Engine
- **Supported engines**: Toyota 1ZZ-FE, 2ZZ-GE (inline 4-cylinder)
- **Supercharger**: Optional (this is why the TMAP sensor is optional)
- **EGR**: None on these engines
- **Firing order**: 1-3-4-2
- **Features**: Optional launch control, variable traction control

### Flash (512KB)

| Address Range | Size | Content |
|---------------|------|---------|
| 0x00000-0x0FFFF | 64KB | Bootloader |
| 0x10000-0x1FFFF | 64KB | Calibration (`CAL_` variables, copied to RAM at startup) |
| 0x20000-0x7FFFF | 384KB | Program code |

### RAM (32KB)

| Address Range | Size | Content |
|---------------|------|---------|
| 0x2F8000-0x2F87FF | 2KB | Decompression RAM (`LEA_` learned parameters, copied from EEPROM at startup) |
| 0x3F8000-0x3FFFFF | 32KB | Internal SRAM (runtime variables) |

### TPU A - Inputs/Timing
Crank/cam position, knock window, wheel speed sensors, ignition coil outputs

### TPU B - Outputs/Injection
Injector timing, VVT/VVL PWM control, ignition feedback

### Hardware Components

- **MCU**: MPC563MZP56 (PowerPC-based, 32-bit, 4.00 MHz crystal)
- **TPU**: Two Time Processor Units (TPU A and TPU B), 16 channels each

| Chip | Purpose |
|------|---------|
| MPC563MZP56 | Main MCU (32-bit PowerPC) |
| MC68HC908JK8 | Safety processor (monitors PPS/TPS) |
| SC33394FDH | Power supply + CAN transceiver |
| VP251 | Industrial CAN transceiver |
| L9613 | K-Line interface (OBD) |
| 25160AN | SPI EEPROM (LEA_ backup storage) |
| TLE6220GP | Quad low-side switch (injectors, VVT/VVL) |
| L9822EPD | Octal serial solenoid driver |
| TLE6209R | H-Bridge for DC motor (throttle) |
| 1NV04 | Power MOSFET |
| 76407D | Power MOSFET (O2 sensor heaters, current sensed via R10 shunt) |
| MPX4001A | Internal pressure sensor |
| L9119D | Knock sensor signal filter and amplifier |
| LM2904 | Dual op-amp (signal conditioning) |
| LM2903 | Dual comparator (signal conditioning) |
| LM6152BCM | High-speed rail-to-rail dual/quad op-amp |
| 27M2C | Dual op-amp |
| SM5A27 | Transient voltage suppressors (protection) |
| MAAC V358 | |
