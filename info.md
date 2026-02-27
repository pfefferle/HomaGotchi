# HomaGotchi

Defensive BLE signature monitoring for Home Assistant.

## What it does

- Monitors BLE advertisements from the Home Assistant Bluetooth network.
- Detects signatures linked to pentest/spoofing BLE activity.
- Exposes a spam `binary_sensor`, dynamic BLE `device_tracker` entities, and a Pwnagotchi `text` entity.

## Sensors

1. `BLE Spam Activity` (`problem` class)
2. `Pentest Device <MAC>` (`device_tracker`, Flipper-family signatures)
3. `Face` (`text`)

Spam and tracker entities support threshold/timeout-based behavior.

## Signature Coverage

- FlipperZero service UUIDs (`00003081/82/83`)
- FlipperZero/ESP32 Marauder payload patterns (`0x8130`, `0x8230`, `0x8330`)
- AppleJuice payload signatures (`07 19 07 .. 20 75 aa 30`)
- Marauder Apple popup payload signatures (`07 0f 00 .. ac 90 85 75 94 65`)
- Apple setup popup payload signatures (`04 04 2a .. 0f 05 c1`)
- SourApple payload signatures (`0f 05 c0/c1 .. 00 00 10`)
- Apple continuity custom-crash signatures (`0f 05 .. .. .. .. .. 00 00 10`)
- Microsoft Swift Pair payload signatures
- Samsung watch-pair payload signatures
- Samsung buds EasySetup payload signatures
- Google Fast Pair payload-frame signatures
- Apple Continuity spoofing
- AirTag spoofing
- Google Fast Pair spoofing
- Microsoft Swift Pair spoofing
- Samsung SmartTag spoofing
- Tile spoofing

## Requirements

- Home Assistant with the `bluetooth` integration enabled.
- At least one local Bluetooth adapter or BLE proxy.

## Safety

This integration is defensive-only and uses passive BLE observation.
