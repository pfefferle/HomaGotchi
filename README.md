# HomaGotchi

Defensive BLE signature monitoring for Home Assistant.

## Scope

This integration is BLE-only and defensive-only:
- Uses the Home Assistant Bluetooth network (`bluetooth` integration scanners/proxies).
- Detects BLE signatures commonly associated with pentest/spoofing tooling.
- Focuses on passive BLE observation and alerting.

## Entities

The integration creates:
- `BLE Spam Activity` (`binary_sensor`, `problem` class): sustained spam behavior.
- `Pentest Device Presence` (`binary_sensor`, `presence` class): direct pentest-device signature presence.
- Dynamic `device_tracker` entities (`Pentest Device <MAC>`): device-style tracking for Flipper/Marauder-like signatures.
- `Face` (`text`): Pwnagotchi status text entity.

Spam and tracker activity auto-reset after the configured inactivity timeout.

## Signatures Detected

- FlipperZero service UUID signatures (`00003081/82/83` variants)
- FlipperZero/ESP32 Marauder payload patterns (`0x8130`, `0x8230`, `0x8330`)
- AppleJuice payload signatures (`07 19 07 .. 20 75 aa 30`)
- Marauder Apple popup payload signatures (`07 0f 00 .. ac 90 85 75 94 65`)
- Apple setup popup payload signatures (`04 04 2a .. 0f 05 c1`)
- SourApple payload signatures (`0f 05 c0/c1 .. 00 00 10`)
- Apple continuity custom-crash signatures (`0f 05 .. .. .. .. .. 00 00 10`)
- Apple Continuity spoofing signatures
- AirTag/Find My spoofing signatures
- Google Fast Pair payload-frame signatures
- Google Fast Pair spoofing signatures
- Microsoft Swift Pair payload signatures
- Microsoft Swift Pair spoofing signatures
- Samsung watch-pair payload signatures
- Samsung buds EasySetup payload signatures
- Samsung SmartTag spoofing signatures
- Tile spoofing signatures

## Project Signature Check

Checked projects and whether they expose concrete BLE signatures usable for detection:
- `n0xa/m5stick-nemo` (`https://github.com/n0xa/m5stick-nemo`): yes, explicit AppleJuice/Apple popup payload byte patterns.
- `BruceDevices/firmware` (`https://github.com/BruceDevices/firmware`): yes, explicit AppleJuice, SourApple, Swift Pair, Samsung, and Fast Pair payload patterns.
- `justcallmekoko/ESP32Marauder` (`https://github.com/justcallmekoko/ESP32Marauder`): yes, concrete BLE payload shapes for SourApple/Swift Pair/Samsung/Fast Pair and Marauder-style Apple popup payloads.
- `jaylikesbunda/Ghost_ESP` (`https://github.com/jaylikesbunda/Ghost_ESP`): yes, explicit BLE packet builders for Apple Continuity (including custom-crash shape), Swift Pair, Samsung EasySetup (watch + buds), and Fast Pair.
- `geo-tp/ESP32-Bus-Pirate` (`https://github.com/geo-tp/ESP32-Bus-Pirate`): no BLE spam payload generator signatures found; Bluetooth code is focused on scan/sniff/pair/HID workflows.
- `0ct0sec/M5PORKCHOP` (`https://github.com/0ct0sec/M5PORKCHOP`): no clear BLE spam payload signatures found in current source tree.
- `7h30th3r0n3/Evil-M5Project` (`https://github.com/7h30th3r0n3/Evil-M5Project`): BLE attack features are present, but stable signature bytes were not reliably extractable from the large monolithic sources during this pass.

## Configuration Options

- `intensity_threshold`: Event count required for the general BLE detector
- `intensity_window`: Rolling seconds window for general BLE detector
- `auto_reset_timeout`: Seconds of inactivity before sensor resets to `off`

## Installation

### HACS

1. Open HACS → Integrations.
2. Add custom repo: `https://github.com/pfefferle/homagotchi`.
3. Install integration.
4. Restart Home Assistant.
5. Add `HomaGotchi` from Settings → Devices & Services.

### Manual

1. Copy `custom_components/homagotchi/` into your Home Assistant `custom_components/`.
2. Restart Home Assistant.
3. Add `HomaGotchi` from Settings → Devices & Services.

## How Detection Works

1. Registers a callback via Home Assistant Bluetooth APIs.
2. Inspects manufacturer data, service UUIDs, and service markers.
3. Applies defensive heuristics (rapid advertising + signature matching).
4. Triggers spam state once threshold is met, and tracks matching Flipper-family devices.
5. Exposes rich attributes for automations and incident review.

## Notes

- This project is intended for defensive awareness and monitoring.
- BLE signature detection can produce false positives depending on your environment.
- Tune thresholds for your location and device density.
