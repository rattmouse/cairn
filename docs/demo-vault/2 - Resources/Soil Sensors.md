---
title: Soil Sensors
tags: [reference, hardware]
updated: 2026-01-22
---

# Soil Sensors

## Resistive

Two exposed probes, measuring conductivity. Cheap, and the electrodes corrode within a few months because you are running current through wet soil. Fine for a demo, useless for a season.

## Capacitive

The sensing element is sealed behind the board's solder mask, so nothing is exposed to the soil. It reads dielectric constant, which tracks water content closely enough. Needs calibration per soil type:

- Oven-dry a sample and read it — that is 0%
- Saturate the same sample and read it — that is 100%
- Interpolate linearly; it is not truly linear, but the error is small in the band that matters

Used in [[Greenhouse Automation]].
