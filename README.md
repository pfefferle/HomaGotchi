# HomaGotchi

Defensive BLE and WiFi monitoring for Home Assistant — with personality.

Inspired by the [Pwnagotchi](https://pwnagotchi.ai/) project and built to detect the attacks that tools like [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder), [FlipperZero](https://flipperzero.one/), and [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) can perform — from the defender's side.

## Scope

This integration is defensive-only:
- Uses the Home Assistant Bluetooth network (`bluetooth` integration scanners/proxies) for BLE signature detection.
- Supports WiFi attack detection via the **HomaGotchi Companion** — an ESP32-S3 device that passively monitors WiFi and reports findings over BLE using the [BTHome v2](https://bthome.io/) protocol.
- Fights back with **defensive retaliation**: broadcasts funny SSID beacons and a pwnagotchi identity when attacks are detected.
- Focuses on passive observation, alerting, and having fun while doing it.

## Entities

The integration creates:

### BLE Sensors
- `BLE Spam Activity` (`binary_sensor`, `problem` class): sustained spam behavior.
- `Pentest Device Presence` (`binary_sensor`, `presence` class): direct pentest-device signature presence.
- Dynamic `device_tracker` entities (`Pentest Device <MAC>`): device-style tracking for Flipper/Marauder-like signatures.

### WiFi Sensors (via Companion device)
- `WiFi Deauth Attack` (`binary_sensor`, `problem` class): deauthentication/disassociation frame floods.
- `Pwnagotchi Detected` (`binary_sensor`, `problem` class): Pwnagotchi beacon frames (MAC `DE:AD:BE:EF:DE:AD` + JSON fallback).
- `Evil Twin Detected` (`binary_sensor`, `problem` class): duplicate SSIDs from different BSSIDs.
- `Beacon Spam Detected` (`binary_sensor`, `problem` class): fake AP flooding from many unique MACs.
- `Probe Flood Detected` (`binary_sensor`, `problem` class): high-rate probe request scanning.
- `Karma Attack Detected` (`binary_sensor`, `problem` class): single BSSID advertising multiple SSIDs (Karma/Pineapple behavior).
- `Pineapple Detected` (`binary_sensor`, `problem` class): suspicious OUI from known pentest hardware (Hak5, Alfa, etc.).
- `Retaliation Active` (`binary_sensor`): indicates when the companion is broadcasting defensive beacons.

### Personality & Gamification
- `Face` (`text`): Reactive pwnagotchi face that changes expression based on detections — sleeping when idle, intense during BLE spam, excited when a pwnagotchi friend is spotted, overwhelmed during multi-threat scenarios.
- `Status` (`text`): Witty context-aware quips like *"someone brought a flipper to the party"*, *"deauth storm, grab an umbrella!"*, or *"who lives in a pineapple under the LAN?"*.
- `Experience Level` (`sensor`): XP system tracking total detections. Levels: Newborn → Script Kiddie Bait → Watchful → Paranoid → Battle-Hardened → War-Scarred Veteran → Legendary Sentinel.
- `Friends Met` (`sensor`): Counts pwnagotchi encounters — the classic "peers met" feature.
- `Age` (`sensor`): Human-readable uptime ("3d 7h 22m").
- `Time Without Incident` (`sensor`): Streak counter that resets on any detection.

All sensors auto-reset after the configured inactivity timeout. Attack detections trigger an **instant BLE broadcast** instead of waiting for the regular 10-second interval.

## Signatures Detected

### BLE Signatures

Detected via Home Assistant's Bluetooth stack — no additional hardware required.

- FlipperZero service UUID signatures (`00003081/82/83` variants)
- FlipperZero/[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) payload patterns (`0x8130`, `0x8230`, `0x8330`)
- [LightBlue](https://punchthrough.com/lightblue/) BLE Explorer app UUID (`DEADF154`) — recon tool detection (source: [GhostBLE](https://github.com/pfefferle/GhostBLE))
- [CatHack](https://github.com/RapidIdentity/CatHack) / Apple Juice attack service UUIDs (source: [GhostBLE](https://github.com/pfefferle/GhostBLE))
- AppleJuice payload signatures ([m5stick-nemo](https://github.com/n0xa/m5stick-nemo), [Bruce](https://github.com/BruceDevices/firmware), [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder))
- Marauder-style Apple popup payload signatures
- Apple setup popup payload signatures
- SourApple continuity payload signatures
- Apple continuity custom-crash signatures ([Ghost_ESP](https://github.com/jaylikesbunda/Ghost_ESP))
- AirTag/Find My spoofing signatures
- Google Fast Pair spoofing and payload-frame signatures
- Microsoft Swift Pair spoofing and payload signatures
- Samsung watch-pair and buds EasySetup payload signatures
- Samsung SmartTag spoofing signatures
- Tile spoofing signatures

Heuristic spoofing signatures (Apple continuity, Fast Pair, Swift Pair, Samsung, Tile) require **both** rapid advertising (<0.3s interval) **and** name mismatch to reduce false positives from legitimate devices.

### WiFi Signatures

Detected via the HomaGotchi Companion device in WiFi promiscuous mode.

- **Deauth/Disassoc floods** — as performed by [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder), [FlipperZero](https://flipperzero.one/), [Ghost_ESP](https://github.com/jaylikesbunda/Ghost_ESP)
- **Pwnagotchi beacons** — well-known MAC `DE:AD:BE:EF:DE:AD` + JSON identity keys (`pwnd_tot`, `identity`)
- **Evil twin APs** — same SSID from different BSSIDs, as used by [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) and similar rogue AP tools
- **Beacon spam** — fake AP flooding from many unique source MACs, as performed by [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) beacon spam mode
- **Probe request floods** — high-rate probe scanning used for reconnaissance
- **Karma / multi-SSID devices** — single BSSID advertising 3+ different SSIDs, characteristic of [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) Karma mode
- **Pineapple OUI detection** — suspicious MAC prefixes from Hak5 (`00:13:37`), Alfa (`00:C0:CA`), and common spoofed/unassigned ranges

## Defensive Retaliation

When the companion device detects an attack, it fights back by broadcasting beacon frames with context-aware SSIDs:

| Threat | Example SSIDs |
|---|---|
| Deauth attack | "Stop deauthing me >:(", "Deauth this, nerd" |
| Flipper/Pineapple | "Nice dolphin you got there", "Flipper go home" |
| Pwnagotchi | "Hello fren! (o_o)", "pwn buddies 4ever" |
| Evil twin | "The real AP is here ->", "Nice try, rogue AP" |
| Generic | "Get off my LAN", "This network fights back" |

It also broadcasts a **pwnagotchi-style identity beacon** (MAC `DE:AD:BE:EF:CA:FE`) with a JSON payload, so other pwnagotchis and scanners see HomaGotchi as a peer on the network.

Retaliation is non-destructive — it only broadcasts beacons visible to WiFi scanners. It does not send deauth frames or interfere with legitimate traffic.

## Project Signature Check

Checked projects and whether they expose concrete BLE signatures usable for detection:
- [`n0xa/m5stick-nemo`](https://github.com/n0xa/m5stick-nemo): yes, explicit AppleJuice/Apple popup payload byte patterns.
- [`BruceDevices/firmware`](https://github.com/BruceDevices/firmware): yes, explicit AppleJuice, SourApple, Swift Pair, Samsung, and Fast Pair payload patterns.
- [`justcallmekoko/ESP32Marauder`](https://github.com/justcallmekoko/ESP32Marauder): yes, concrete BLE payload shapes for SourApple/Swift Pair/Samsung/Fast Pair and Marauder-style Apple popup payloads. Pwnagotchi detection logic (MAC + JSON parsing) was referenced for the companion firmware.
- [`jaylikesbunda/Ghost_ESP`](https://github.com/jaylikesbunda/Ghost_ESP): yes, explicit BLE packet builders for Apple Continuity (including custom-crash shape), Swift Pair, Samsung EasySetup (watch + buds), and Fast Pair.
- [`pfefferle/GhostBLE`](https://github.com/pfefferle/GhostBLE): yes, LightBlue and CatHack/Apple Juice service UUIDs for BLE device identification.
- `geo-tp/ESP32-Bus-Pirate`: no BLE spam payload generator signatures found.
- `0ct0sec/M5PORKCHOP`: no clear BLE spam payload signatures found.
- `7h30th3r0n3/Evil-M5Project`: BLE attack features are present, but stable signature bytes were not reliably extractable.

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
3. Applies defensive heuristics (rapid advertising + name mismatch + signature matching).
4. Triggers spam state once threshold is met, and tracks matching Flipper-family devices.
5. Exposes rich attributes for automations and incident review.

### WiFi Detection (Companion)
1. The HomaGotchi Companion device runs in WiFi promiscuous mode, capturing raw 802.11 management frames.
2. It counts deauth/disassoc/probe frames, detects pwnagotchi beacons (by MAC and JSON keys), tracks SSID/BSSID pairs for evil twin and karma detection, monitors beacon source MAC diversity for spam detection, and checks OUIs against known pentest hardware.
3. When an attack is detected, it **immediately broadcasts** a BTHome v2 BLE advertisement with the collected counters and a flags bitmask, then **retaliates** with defensive beacon frames. Routine reports are sent every 10 seconds.
4. Home Assistant receives these advertisements via its Bluetooth stack — no WiFi pairing or network connection is needed.
5. The integration parses the BTHome payload, deduplicates by packet ID, and updates the WiFi binary sensors.

## HomaGotchi Companion Firmware

The companion firmware lives in `firmware/homagotchi-companion/` and targets the **M5Stack Atom S3** (ESP32-S3). It uses PlatformIO with the ESP-IDF framework.

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
| Pwnagotchi beacons | MAC `DE:AD:BE:EF:DE:AD` match + JSON key fallback (`pwnd_tot`, `identity`) |
| Evil twin APs | Tracks SSID→BSSID mappings; flags same SSID from a different BSSID |
| Beacon spam | Tracks unique beacon source MACs; flags when 30+ unique MACs seen per interval |
| Probe flood | Counts probe request frames (subtype 0x04); flags at 50+ per interval |
| Karma / multi-SSID | Tracks BSSID→SSID mappings; flags when one BSSID advertises 3+ SSIDs |
| Pineapple device | Checks beacon source MAC OUI against known pentest hardware (Hak5, Alfa, etc.) |

### BTHome v2 Payload Format

The BLE advertisement contains four `count_u16` BTHome objects:

| Object | Content |
|---|---|
| count[0] | Deauth frame count |
| count[1] | Disassoc frame count |
| count[2] | Probe request count |
| count[3] | Flags bitmask (bit 0: deauth, 1: pwnagotchi, 2: evil twin, 3: beacon spam, 4: probe flood, 5: karma, 6: pineapple, 7: retaliation active) |

### Configuration

All tunables are in `include/config.h`:
- `HG_DEVICE_NAME` — BLE advertised name (default: `"Gotchi"`)
- `HG_CHANNEL_HOP_MS` — channel hop interval (default: 500 ms)
- `HG_REPORT_INTERVAL_MS` — BLE broadcast interval (default: 10 s)
- `HG_ATTACK_THRESHOLD` — deauth+disassoc frames to flag an attack (default: 5)
- `HG_PROBE_FLOOD_THRESHOLD` — probe requests to flag a flood (default: 50)
- `HG_BEACON_SPAM_THRESHOLD` — unique beacon MACs to flag spam (default: 30)
- `HG_KARMA_SSID_THRESHOLD` — SSIDs per BSSID to flag karma (default: 3)
- `HG_RETALIATION_BURST` — beacon frames per retaliation burst (default: 5)
- `HG_MAX_AP_ENTRIES` — AP table size for evil twin / karma tracking (default: 64)
- `HG_MAX_BEACON_MACS` — beacon MAC tracker size (default: 64)

### Notes

- The companion uses WiFi promiscuous mode for passive capture and BLE legacy advertising for reporting — it never connects to any WiFi network.
- Evil twin detection may produce false positives in mesh/roaming environments where multiple APs legitimately share the same SSID. The AP table resets every ~5 minutes to reduce stale entries.
- Pwnagotchi detection uses the same approach as [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder): matching the well-known source MAC `DE:AD:BE:EF:DE:AD`, with a fallback scan for JSON identity keys in the beacon body.
- Retaliation beacons use random locally-administered MACs and are broadcast on the current monitoring channel only.

## Acknowledgments

- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) by justcallmekoko — WiFi/BLE offensive tool whose attack signatures and pwnagotchi detection logic informed this project's defensive detection.
- [Wall of Flippers](https://github.com/K3YOMI/Wall-of-Flippers) — FlipperZero BLE signature database.
- [GhostBLE](https://github.com/pfefferle/GhostBLE) — BLE privacy scanner whose device UUID database was referenced for LightBlue and CatHack detection.
- [BTHome](https://bthome.io/) — open BLE protocol used for companion device communication.
- [Pwnagotchi](https://pwnagotchi.ai/) — AI-powered WiFi audit tool whose beacon format is detected (and greeted as a friend).

## Notes

- This project is intended for defensive awareness and monitoring.
- BLE signature detection can produce false positives depending on your environment.
- WiFi evil twin detection may flag legitimate mesh/roaming setups.
- Retaliation is non-destructive — only beacon broadcasts, no deauth or jamming.
- Tune thresholds for your location and device density.
