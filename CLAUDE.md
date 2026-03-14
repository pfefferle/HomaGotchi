# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HomaGotchi — a defensive WiFi/BLE monitoring integration for Home Assistant, inspired by Pwnagotchi. Two components:

1. **HA Integration** (`custom_components/homagotchi/`) — Python, detects BLE attack signatures via HA's Bluetooth API, receives WiFi detections from the companion via BTHome v2
2. **ESP32 Companion Firmware** (`firmware/homagotchi-companion/`) — C/ESP-IDF, passive WiFi monitor on M5Stack AtomS3, reports via BLE

## Build Commands

### Companion Firmware (PlatformIO + ESP-IDF)

```bash
~/.platformio/penv/bin/pio run                  # Build
~/.platformio/penv/bin/pio run -t upload         # Flash
~/.platformio/penv/bin/pio device monitor        # Serial monitor (115200 baud)
~/.platformio/penv/bin/pio run -t clean          # Clean
```

### HA Integration

```bash
pip install -r requirements.txt                  # Dev dependencies
python -m pytest test_env/                       # Run tests (if any)
```

No linter is configured for either component.

## Architecture

### HA Integration (`custom_components/homagotchi/`)

- **binary_sensor.py** — Two sensor families:
  - `_BaseBleActivitySensor`: BLE spam/presence detection using HA Bluetooth callbacks, rolling window + intensity threshold + auto-reset
  - `CompanionWifiSensor`: Parses BTHome v2 advertisements from companion, maps flags bitmask to individual WiFi threat sensors
- **bthome.py** — BTHome v2 parser (UUID `0xFCD2`). Companion sends 4 `count` objects: deauth, disassoc, probes, flags bitmask
- **sensor.py** — Gamification: XP levels, friend count, uptime, incident streak. Subscribes to `EVENT_DETECTION`
- **text.py** — Reactive pwnagotchi face + status quips. Subscribes to `EVENT_DETECTION`
- **device_tracker.py** — Dynamic entities for each detected BLE pentest device
- **signatures.py** — BLE signature matching (FlipperZero, AppleJuice, SourApple, Google Fast Pair, Samsung, etc.)
- **const.py** — All constants: flags, faces, quips, signature definitions, config keys

**Event bus pattern:** Binary sensors fire `EVENT_DETECTION` with `{"detector": id, "is_on": bool}`. Text, sensor, and gamification entities subscribe to react. This decouples detectors from downstream entities.

### Companion Firmware (`firmware/homagotchi-companion/`)

Four subsystems as .c/.h pairs orchestrated by `main.c`:

- **wifi_sniffer** — Promiscuous mode on all 13 channels. `sniffer_cb()` ISR classifies frames, updates counters/flags via spinlock
- **bthome** — Encodes `wifi_report_t` into BTHome v2 BLE advertisements (UUID 0xFCD2)
- **retaliation** — Raw 802.11 beacon injection via `esp_wifi_80211_tx()`. Pwngrid identity beacons + funny SSID beacons
- **main** — FreeRTOS task on core 1: channel hop (500ms), collect (10s), urgent alerts (throttled 1/sec)

**Data flow:**
```
WiFi frames → sniffer_cb() [ISR, spinlock] → counters/flags
monitor_task → wifi_sniffer_collect() → retaliation_fire() → bthome_broadcast()
             → retaliation_send_gotchi_beacon() [every channel hop]
```

**Key files:** All thresholds in `include/config.h`. Flag bits (`HG_FLAG_*`) shared between firmware and HA integration. pwngrid protocol documented in `firmware/homagotchi-companion/docs/pwngrid-protocol.md`.

**Self-detection:** Not needed. ESP32 radio cannot TX and RX simultaneously. Our pwngrid beacons use `PWNGRID_MAC` (`DE:AD:BE:EF:DE:AD`) in Address2 and `SESSION_MAC` (`DE:AD:BE:EF:CA:FE`) in Address3 (per pwngrid protocol: Address3 is a unique session ID).

**Hardware:** M5Stack AtomS3 (ESP32-S3), USB JTAG console, 3MB factory partition.

## Detection Agents

Each detection is implemented in the companion firmware (`wifi_sniffer.c` `sniffer_cb()`) and surfaced as a binary sensor in HA (`binary_sensor.py`). Retaliation responses in `retaliation.c`. Thresholds in `config.h`.

### Deauth / Disassoc (`HG_FLAG_DEAUTH`)

Counts management frame subtypes `0x0C` (deauth) and `0x0A` (disassoc). Combined count >= `HG_ATTACK_THRESHOLD` (5) per 10s interval triggers the flag. Enhanced detection:
- **Broadcast deauth instant-flag**: Deauths to `FF:FF:FF:FF:FF:FF` flag at threshold 2
- **Reason code weighting**: Codes 1 (unspecified), 2 (prev auth invalid), and 7 (Class 3 from non-assoc STA) are double-counted — these are the defaults used by attack tools
- Retaliates with `SSIDS_DEAUTH[]`

**Reference implementations:**
- **ESP32Marauder** — `~/Code/ESP32Marauder/esp32_marauder/WiFiScan.cpp`: `sendDeauthFrame()` (~line 8774), `RunDeauthScan()` (~line 5165), reason code 2
- **minigotchi-ESP32** — `~/Code/minigotchi-ESP32/minigotchi-ESP32/deauth.cpp`: frame construction with `esp_wifi_80211_tx()`, overrides `ieee80211_raw_frame_sanity_check`, reason code 1, sends 150+ frames per target at 102ms intervals
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/core/wsl_bypasser.cpp` bidirectional deauth (reason 7 forward AP→Client, reason 1 reverse Client→AP), bursts of 3-8 at 180ms, RSSI-scaled cooldown, skips PMF-protected networks
- **Nugget-Invader** — [Hamspiced/Nugget-Invader](https://github.com/Hamspiced/Nugget-Invader): `WiFiScanner.cpp` basic deauth, reason code 1, 50ms inter-packet, no MAC randomization, ESP8266 `wifi_send_pkt_freedom()`

### Pwnagotchi (`HG_FLAG_PWNAGOTCHI`)

Three detection methods in `is_pwnagotchi_beacon()`:
1. MAC match — Address2 or BSSID == `DE:AD:BE:EF:DE:AD`
2. pwngrid IE tags — 2+ distinct tags from 222-226 (0xDE-0xE2)
3. JSON fallback — payload contains `"pwnd_tot"` or `"\"identity\""`

Scans all management frame types with correct IE offset (36 for beacons, 24 for action frames). Retaliates with `SSIDS_PWNAGOTCHI[]` and sends a pwngrid identity beacon.

**Reference implementations:**
- **minigotchi-ESP32** — `~/Code/minigotchi-ESP32/minigotchi-ESP32/frame.cpp`: pwngrid beacon packing with payload IDs `0xDE-0xE2`, MAC `de:ad:be:ef:de:ad`, WPA flags `0x0411`, chunked JSON in IE 222. `pwnagotchi.cpp`: detection via promiscuous mode, JSON parsing from byte 38
- **pwnagotchi** — `~/Code/pwnagotchi/pwnagotchi/grid.py`: pwngrid API client (port 8666), `advertise()`. `mesh/peer.py`: `Peer` class with identity fields. `identity.py`: key generation via `pwngrid -generate`
- **ESP32Marauder** — `WiFiScan.cpp`: `pwnSnifferCallback()` (~line 6540), detects `de:ad:be:ef:de:ad` and parses JSON

### Evil Twin (`HG_FLAG_EVIL_TWIN`)

Tracks SSID/BSSID pairs in `s_ap_table[]` (64 entries). Same SSID from a different BSSID triggers the flag. Table resets every 30 collect cycles (~5 min). Enhanced with RSSI tracking — new BSSID with >5dB stronger signal than original is logged as suspect. Retaliates with `SSIDS_EVIL_TWIN[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `EvilPortal.h/.cpp` for captive portal with DNS + AsyncWebServer, `RunEvilPortal()` (~line 3521)
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): evil twin with captive portal on M5Stack, clones target SSID + DNS redirect, random MAC per beacon via `setRandomMAC_APKarma()`

### Beacon Spam (`HG_FLAG_BEACON_SPAM`)

Multiple detection triggers:
1. **MAC diversity**: >= 30 unique beacon source MACs with >50% locally-administered
2. **SSID diversity**: >= 15 unique beacon SSIDs per interval
3. **Known attack SSIDs**: Instant flag on wordlist match (Marauder rick_roll, funny_beacon, M5PORKCHOP "USSID FATHERSHIP", etc.)
4. **Entropy analysis**: High-entropy SSIDs (15+ chars, no spaces, mixed alphanumeric) lower MAC threshold to half

Resets every 10s. Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `broadcastRandomSSID()` (~line 11436), `WIFI_ATTACK_BEACON_SPAM` mode; `broadcastCustomBeacon()` (~line 11462); `broadcastSetSSID()` with `rick_roll[]` array (~line 11494); `funny_beacon[]` with "Abraham Linksys", "FBI Surveillance Van 4", etc.
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/bacon.cpp` BACON mode — beacon frame with SSID `"USSID FATHERSHIP"` on channel 6, vendor IE OUI `50:52:4B` ("PRK") type `0x01` embedding nearby AP fingerprints, capability `0x0104` (ESS + short preamble), tiered TX rates (50/100/150ms)

### Probe Flood (`HG_FLAG_PROBE_FLOOD`)

Two detection methods:
1. **Count threshold**: >= 50 probe requests per 10s interval
2. **MAC churn**: >= 20 unique probe source MACs per interval (catches Evil-M5 style MAC rotation at 500ms intervals)

Also records probe SSIDs in a ring buffer for karma correlation. Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `RunProbeScan()` (~line 5271), `sendProbeAttack()` (~line 8714) with random MACs
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): `probeAttack()` generates random 32-char SSIDs, changes MAC via `esp_wifi_set_mac()` every 500ms, channels 1-14

### Karma (`HG_FLAG_KARMA`)

Same AP table as evil twin. Two detection methods:
1. **Multi-SSID threshold**: One BSSID broadcasting >= 3 different SSIDs
2. **Probe-beacon correlation**: Beacon SSID matches a recently-probed SSID and BSSID already has 2+ SSIDs — catches karma before multi-SSID threshold

Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): `loopAutoKarma()` sniffs probes then creates matching APs, stores up to 512 SSIDs, unicast-forced MAC (`mac[0] &= 0xFE`), configurable AP duration
- External: [hostapd-mana](https://github.com/sensepost/hostapd-mana) (karma-enabled hostapd), [bettercap](https://github.com/bettercap/bettercap) `wifi.ap` with `--karma`

### Pineapple (`HG_FLAG_PINEAPPLE`)

Multi-method detection:
1. **OUI matching**: 15 known attack device OUI prefixes with suspicion levels (ALWAYS vs WHEN_OPEN): Hak5, Alfa, Shenzhen Century, Panda Wireless, MediaTek, GL.iNet, Realtek, Ralink, spoofed `DE:AD:BE`
2. **Capability minimalism**: Capability `0x0001` or `0x0104` with <= 3 tagged IEs (real APs have many more)
3. **Attack vendor IEs**: Vendor IE with OUI `50:52:4B` ("PRK") type `0x01` — M5PORKCHOP BACON fingerprint

Skipped if already identified as pwnagotchi. Retaliates with `SSIDS_FLIPPER[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `RunPineScan()` (~line 4492), `pineScanSnifferCallback()` (~line 6626), OUI table (~line 6554) with suspicion levels
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/bacon.cpp` BACON mode uses vendor IE OUI `50:52:4B` to broadcast AP fingerprints

### Auth Flood (`HG_FLAG_AUTH_FLOOD`)

Counts authentication frames (subtype `0x0B`). Count >= `HG_AUTH_FLOOD_THRESHOLD` (20) per 10s interval triggers the flag. Detects auth DoS and PMKID capture attempts. Retaliates with `SSIDS_AUTH_FLOOD[]`.

**Reference implementations:**
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/oink.cpp` sends association requests for active PMKID extraction, searches EAPOL M1 for KDE pattern `DD 14 00 0F AC 04` + 16-byte PMKID

### BLE Signatures (HA-side only, no companion needed)

~20+ patterns detected via HA Bluetooth API in `signatures.py` and `binary_sensor.py`:
- FlipperZero service UUIDs and payloads
- AppleJuice / Apple continuity spoofing (multiple variants)
- SourApple attacks
- Google Fast Pair / Microsoft Swift Pair spoofing
- Samsung device pairing attacks
- Tile/AirTag spoofing
- Heuristic: rapid advertising (<0.3s) + name mismatch

**Reference implementations:**
- **ESP32Marauder** — BLE spam modes in `WiFiScan.cpp`
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/piggyblues.cpp` — 31 Apple payloads (21 audio devices + 10 setup), 52 Android FastPair model IDs, 10 Samsung (6 Buds + 4 Watch), Windows SwiftPair. Uses NimBLE with random BLE addresses, 200ms burst interval, vendor-aware targeting (selects payload matching nearby device type)
- Flipper Zero firmware and community apps for BLE spam patterns

### Cross-detector Correlation

The firmware logs correlated attack patterns that indicate coordinated attacks:
- **Deauth + Evil Twin** = active AP attack (deauth clients off legitimate AP, then clone it)
- **Probe Flood + Karma** = karma attack in progress (flood probes to discover SSIDs, then respond)
- **Pwnagotchi + Deauth** = pwnagotchi actively hunting (not just observing)

### Peer detector projects

- **HaxxDetector** — [DevKitty-io/HaxxDetector](https://github.com/DevKitty-io/HaxxDetector): Simple deauth detector for WiFi Nugget (ESP8266). Extremely low threshold (1 frame per 1.3s window) — useful as sensitivity reference but high false positive rate. No evil twin, beacon spam, or BLE detection.
- **Piglet** — [Hamspiced/piglet](https://github.com/Hamspiced/piglet): Passive wardriver only (WiGLE CSV export). No attack capabilities or detection features. Targets Seeed XIAO ESP32-S3/C5/C6.
