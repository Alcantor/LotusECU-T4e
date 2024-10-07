## Introduction

On race track and with the OEM configuration, my Exige S2 quickly suffers from heat.

The ECU retards the ignition so drastically that my car felt slower than a
naturally aspired 2ZZ. I felt a little disappointed to have a supercharger and
not be able to really enjoy it.

Lotus is very protective and power is progressively reduced when coolant water is
above 90°C and/or when intake air temperature (after intercooler) is above 30°C.

With 110°C coolant and 70°C intake temperatue, the ECU retards the timing up to
11 degrees.

Air/Water Intercooling would probably have helped a lot, but it's expensive and
it's a non reversible modification. When I do a modification on my car, I like
to be able to revert to stock.

The ProAlloy bigger Air/Air intercooler with the side scoop supplementary air
feed helped to reduce the temperature by approximately 15°C, but this is by far
not enough to retrieve all the power.

So the idea to use E85 came into my mind.

## The patch

This patch allows the addition of flex-fuel capability to the OEM ECU.

Various tables have been added for different injection and ignition values.

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

## Octane of Ethanol Fuel Blend

There are online tool that calculate the octane value of an ethanol blend. Most
of them are incorrect. The octane value of an ethanol blend is not linearly
related to the ethanol content of the mix.

I prefer this formula from C. Wang and his study about ethanol blends:

$NOI = -0.01983 * vol^2 + 2.8512 * vol$

$RON_{blend} = (NOI * (RON_{ethanol} - RON_{base})) / 100 + RON_{base}$

This formula does not take the cooling effect into account.

## So E85 worth it?

Definitively. Just looking at my coolant temperature gauge, I can tell that the
cooling power of ethanol is tremendous.

Even on a hot track day with an outside temperature of 30°C and the A/C on, I
was able to keep my coolant temperature around 90-95°C. With regular gasoline,
it would be above 105°C for sure.

I not only have more power (around +35 WHP), but more importantly, I don't lose
any power after a track lap.

On the downside, the higher consumption means I can't last half a day on the
track without refueling (original tank).

I'm also concerned about water contamination in my engine oil due to the
hygroscopic nature of ethanol. At my next oil change, I will verify this by
doing a crackle test.

