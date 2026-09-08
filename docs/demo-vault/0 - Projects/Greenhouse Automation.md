---
title: Greenhouse Automation
tags: [hardware, garden, project]
updated: 2026-04-18
---

# Greenhouse Automation

A moisture sensor, a relay, and a pump on the back porch. The whole point is that it keeps working when the house wifi doesn't, so every decision below leans offline.

> [!NOTE]
> The sensor reads *capacitance*, not resistance. Resistive probes corrode into uselessness within a season — see [[Soil Sensors]] for the comparison.

## Where it stands

- [x] Sensor calibrated against oven-dried soil
- [x] Relay wired through an opto-isolator
- [ ] Enclosure printed and sealed
- [ ] Two-week unattended run

## Watering thresholds

| Bed | Dry (%) | Target (%) | Pump (s) |
| --- | --- | --- | --- |
| Tomatoes | 28 | 45 | 90 |
| Herbs | 34 | 50 | 45 |
| Seedlings | 40 | 55 | 20 |

Seedlings get the narrowest band and the shortest burst — overwatering kills far more of them than drought does.

## The control loop

```python
def tick(bed, sensor, pump):
    moisture = sensor.read_percent()
    if moisture < bed.dry:
        pump.run(seconds=bed.burst)
        log("watered %s at %d%%" % (bed.name, moisture))
    return moisture
```

Called once every ten minutes from `cron`. No state is kept between ticks on purpose: if the controller reboots mid-season it reads the soil again and carries on.

## Open questions

1. Does the pump need a check valve, or is the head low enough to ignore?
2. What happens on a **week of rain** — should the loop read a forecast, or is that exactly the network dependency I was avoiding?
3. ~~Battery backup~~ — mains is fine, the porch outlet is on the fridge circuit.

Related: [[Drip Irrigation Notes]] · [[Weekly Review]]
