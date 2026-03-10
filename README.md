# HomaGotchi

Defensive BLE and WiFi monitoring for Home Assistant.

## Scope

This integration is defensive-only:
- Uses the Home Assistant Bluetooth network (`bluetooth` integration scanners/proxies) for BLE signature detection.
- Supports WiFi attack detection via the **HomaGotchi Companion** — an ESP32-S3 device that passively monitors WiFi and reports findings over BLE using the [BTHome v2](https://bthome.io/) protocol.
- Focuses on passive observation and alerting.

## Entities

The integration creates:

### BLE Sensors
- `BLE Spam Activity` (`binary_sensor`, `problem` class): sustained spam behavior.
- `Pentest Device Presence` (`binary_sensor`, `presence` class): direct pentest-device signature presence.
- Dynamic `device_tracker` entities (`Pentest Device <MAC>`): device-style tracking for Flipper/Marauder-like signatures.
- `Face` (`text`): Pwnagotchi status text entity.

### WiFi Sensors (via Companion device)
- `WiFi Deauth Attack` (`binary_sensor`, `problem` class): detects deauthentication/disassociation frame floods.
- `WiFi Pwnagotchi` (`binary_sensor`, `problem` class): detects Pwnagotchi beacon frames.
- `WiFi Evil Twin` (`binary_sensor`, `problem` class): detects duplicate SSIDs broadcast from different BSSIDs.

All sensors auto-reset after the configured inactivity timeout.

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
- `wifi_deauth_threshold`: Minimum deauth/disassoc frame count to trigger the WiFi deauth sensor (default: 5)

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

### BLE Detection
1. Registers a callback via Home Assistant Bluetooth APIs.
2. Inspects manufacturer data, service UUIDs, and service markers.
3. Applies defensive heuristics (rapid advertising + signature matching).
4. Triggers spam state once threshold is met, and tracks matching Flipper-family devices.
5. Exposes rich attributes for automations and incident review.

### WiFi Detection (Companion)
1. The HomaGotchi Companion device runs in WiFi promiscuous mode, capturing raw 802.11 management frames.
2. It counts deauthentication and disassociation frames, parses beacon IEs for Pwnagotchi signatures, and tracks SSID/BSSID pairs to detect evil twins.
3. Every 10 seconds, it broadcasts a BTHome v2 BLE advertisement with the collected counters and boolean flags.
4. Home Assistant receives these advertisements via its Bluetooth stack — no WiFi pairing or network connection is needed.
5. The integration parses the BTHome payload, deduplicates by packet ID, and updates the WiFi binary sensors.

## HomaGotchi Companion Firmware

The companion firmware lives in `firmware/homagotchi-companion/` and targets the **M5Stack Atom S3** (ESP32-S3).

### Building & Flashing

```bash
cd firmware/homagotchi-companion
pio run                          # build
pio run -t upload                # flash via USB
pio device monitor               # serial monitor (115200 baud)
```

### What It Detects

| Threat | Method |
|---|---|
| Deauth/Disassoc floods | Counts management frames with subtype 0x0C / 0x0A |
| Pwnagotchi beacons | Parses vendor-specific IEs (tag 221) for `pwnd` / `pwnagotchi` strings |
| Evil twin APs | Tracks SSID→BSSID mappings; flags same SSID from a new BSSID |

### Configuration

All tunables are in `include/config.h`:
- `HG_DEVICE_NAME` — BLE advertised name (default: `"Gotchi"`)
- `HG_CHANNEL_HOP_MS` — channel hop interval (default: 500 ms)
- `HG_REPORT_INTERVAL_MS` — BLE broadcast interval (default: 10 s)
- `MAX_AP_ENTRIES` — AP table size for evil twin tracking (default: 64)

### Notes

- The companion uses WiFi promiscuous mode for passive capture and BLE legacy advertising for reporting — it never connects to any WiFi network.
- Evil twin detection may produce false positives in mesh/roaming environments where multiple APs legitimately share the same SSID.

## Notes

- This project is intended for defensive awareness and monitoring.
- BLE signature detection can produce false positives depending on your environment.
- WiFi evil twin detection may flag legitimate mesh/roaming setups.
- Tune thresholds for your location and device density.
