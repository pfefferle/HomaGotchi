# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HomaGotchi Companion — ESP32-S3 firmware (M5Stack AtomS3) that passively monitors WiFi management frames, detects attacks, and reports to Home Assistant via BTHome v2 BLE advertisements. When attacks are detected, it broadcasts deterrent beacons with funny SSIDs and advertises itself as a pwngrid peer so real pwnagotchis see it.

## Build Commands

PlatformIO with ESP-IDF framework. The `pio` binary lives at `~/.platformio/penv/bin/pio`.

```bash
# Build
~/.platformio/penv/bin/pio run

# Flash to device
~/.platformio/penv/bin/pio run -t upload

# Monitor serial output (115200 baud)
~/.platformio/penv/bin/pio device monitor

# Clean build
~/.platformio/penv/bin/pio run -t clean
```

There is no test infrastructure or linter configured.

## Architecture

Four subsystems, each a .c/.h pair, orchestrated by `main.c`:

- **wifi_sniffer** — Promiscuous mode capture on all 13 channels. The `sniffer_cb()` ISR-context callback classifies management frames and updates counters/flags protected by a spinlock (`s_counter_mux`). Detects 8 threat types: deauth, pwnagotchi, evil twin, beacon spam, probe flood, karma, pineapple, auth flood.
- **bthome** — Encodes `wifi_report_t` into BTHome v2 service data (UUID 0xFCD2) and broadcasts as non-connectable BLE advertisements. Home Assistant auto-discovers devices named "Gotchi".
- **retaliation** — Injects raw 802.11 beacon frames via `esp_wifi_80211_tx()`. Two modes: pwngrid identity beacons (Address2=`DE:AD:BE:EF:DE:AD`, IE 222 with JSON) and funny SSID beacons with random MACs.
- **main** — FreeRTOS task (`monitor_task`) on core 1: hops channels every 500ms, collects reports every 10s, fires urgent broadcasts when new flags appear (throttled to 1/sec).

### Data flow

```
WiFi frames → sniffer_cb() [ISR, spinlock] → counters/flags
monitor_task [10ms loop] → wifi_sniffer_collect() → retaliation_fire() → bthome_broadcast()
                         → retaliation_send_gotchi_beacon() [every channel hop]
```

### Key constants

All tuneable parameters are in `include/config.h`. Detection flag bits (`HG_FLAG_*`) are shared between firmware and the Home Assistant integration.

### pwngrid protocol

The pwnagotchi peer advertisement format is documented in `docs/pwngrid-protocol.md`. Critical detail: pwngrid's BPF filter requires beacon frames with Address2=`DE:AD:BE:EF:DE:AD` — not action frames.

### Self-detection

Not needed. ESP32 radio cannot TX and RX simultaneously — we never see our own beacons.
Our pwngrid beacons use `PWNGRID_MAC` (`DE:AD:BE:EF:DE:AD`) in both Address2 and Address3
(matching minigotchi format). No self-detection filter is applied in the sniffer.

## Detection Agents

Each detection is implemented in `wifi_sniffer.c` inside `sniffer_cb()`. Retaliation responses are in `retaliation.c`. Thresholds live in `config.h`.

### Deauth / Disassoc (`HG_FLAG_DEAUTH`)

Counts management frame subtypes `0x0C` (deauth) and `0x0A` (disassoc). Combined count >= `HG_ATTACK_THRESHOLD` (5) per 10s interval triggers the flag. Enhanced detection:
- **Broadcast deauth instant-flag**: Deauths to `FF:FF:FF:FF:FF:FF` flag at threshold 2
- **Reason code weighting**: Codes 1, 2, and 7 are double-counted (attack tool defaults)

Retaliates with `SSIDS_DEAUTH[]`.

**Reference implementations:**
- **ESP32Marauder** — `~/Code/ESP32Marauder/esp32_marauder/WiFiScan.cpp`: `sendDeauthFrame()` (line ~8774), reason code 2
- **minigotchi-ESP32** — `~/Code/minigotchi-ESP32/minigotchi-ESP32/deauth.cpp`: frame construction with `esp_wifi_80211_tx()`, reason code 1, overrides `ieee80211_raw_frame_sanity_check`
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/core/wsl_bypasser.cpp` bidirectional deauth (reason 7 forward, reason 1 reverse), bursts of 3-8 at 180ms, disassoc with reason 8
- **Nugget-Invader** — [Hamspiced/Nugget-Invader](https://github.com/Hamspiced/Nugget-Invader): `WiFiScanner.cpp` basic deauth, reason code 1, 50ms interval, ESP8266 `wifi_send_pkt_freedom()`

### Pwnagotchi (`HG_FLAG_PWNAGOTCHI`)

Three detection methods in `is_pwnagotchi_beacon()`:
1. MAC match — Address2 or BSSID == `DE:AD:BE:EF:DE:AD`
2. pwngrid IE tags — 2+ distinct tags from 222-226 (0xDE-0xE2)
3. JSON fallback — payload contains `"pwnd_tot"` or `"\"identity\""`

Scans all management frame types with correct IE offset (36 for beacons, 24 for action frames). Retaliates with `SSIDS_PWNAGOTCHI[]` and sends a pwngrid identity beacon.

**Reference implementations:**
- **minigotchi-ESP32** — `~/Code/minigotchi-ESP32/minigotchi-ESP32/frame.cpp`: pwngrid beacon packing with payload IDs `0xDE-0xE2`, MAC `de:ad:be:ef:de:ad`, WPA flags `0x0411`, chunked JSON in IE 222. `pwnagotchi.cpp`: detection via promiscuous mode, JSON parsing from byte 38
- **pwnagotchi** — `~/Code/pwnagotchi/pwnagotchi/grid.py`: pwngrid API client (port 8666), `advertise()`, `set_advertisement_data()`. `mesh/peer.py`: `Peer` class with `name`, `identity`, `face`, `pwnd_run`, `pwnd_tot`, `epoch`. `identity.py`: key generation via `pwngrid -generate`
- **ESP32Marauder** — `WiFiScan.cpp`: `pwnSnifferCallback()` (line ~6540), detects `de:ad:be:ef:de:ad` and parses JSON

### Evil Twin (`HG_FLAG_EVIL_TWIN`)

Tracks SSID/BSSID pairs in `s_ap_table[]` (64 entries). Same SSID from a different BSSID triggers the flag. Enhanced with RSSI tracking — new BSSID with >5dB stronger signal is logged as suspect. Table resets every 30 collect cycles (~5 min). Retaliates with `SSIDS_EVIL_TWIN[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `EvilPortal.h/.cpp` for evil portal (captive portal with DNS + AsyncWebServer), `RunEvilPortal()` (line ~3521)
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): evil twin with captive portal, clones SSID + DNS redirect, random MAC per beacon

### Beacon Spam (`HG_FLAG_BEACON_SPAM`)

Multiple detection triggers:
1. **MAC diversity**: >= 30 unique beacon MACs with >50% locally-administered
2. **SSID diversity**: >= 15 unique SSIDs per interval
3. **Known attack SSIDs**: Instant flag on wordlist match (15 entries: Marauder rick_roll/funny_beacon, M5PORKCHOP "USSID FATHERSHIP", etc.)
4. **Entropy analysis**: High-entropy SSIDs (15+ chars, no spaces, mixed alphanumeric) lower MAC threshold to half

Resets every 10s. Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `broadcastRandomSSID()` (line ~11436), `broadcastSetSSID()` with `rick_roll[]`/`funny_beacon[]` arrays
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/bacon.cpp` BACON mode — SSID `"USSID FATHERSHIP"` on channel 6, vendor IE OUI `50:52:4B` ("PRK") type `0x01`, capability `0x0104`

### Probe Flood (`HG_FLAG_PROBE_FLOOD`)

Two detection methods:
1. **Count threshold**: >= 50 probe requests per 10s
2. **MAC churn**: >= 20 unique probe source MACs per interval

Records probe SSIDs in ring buffer for karma correlation. Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `sendProbeAttack()` (line ~8714) with random MACs
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): `probeAttack()` random 32-char SSIDs, MAC rotation every 500ms

### Karma (`HG_FLAG_KARMA`)

Two detection methods using the same AP table as evil twin:
1. **Multi-SSID**: One BSSID broadcasting >= 3 SSIDs
2. **Probe-beacon correlation**: Beacon SSID matches recently-probed SSID and BSSID already has 2+ SSIDs

Retaliates with `SSIDS_GENERIC[]`.

**Reference implementations:**
- **Evil-M5Project** — [7h30th3r0n3/Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project): `loopAutoKarma()` sniffs probes then creates matching APs, up to 512 SSIDs
- External: [hostapd-mana](https://github.com/sensepost/hostapd-mana), [bettercap](https://github.com/bettercap/bettercap) `wifi.ap --karma`

### Pineapple (`HG_FLAG_PINEAPPLE`)

Multi-method detection:
1. **OUI matching**: 15 known prefixes with suspicion levels (Hak5, Alfa, MediaTek, GL.iNet, Realtek, Ralink, etc.)
2. **Capability minimalism**: Capability `0x0001` or `0x0104` with <= 3 IEs
3. **Attack vendor IEs**: OUI `50:52:4B` ("PRK") type `0x01` — M5PORKCHOP BACON fingerprint

Skipped if pwnagotchi. Retaliates with `SSIDS_FLIPPER[]`.

**Reference implementations:**
- **ESP32Marauder** — `WiFiScan.cpp`: `pineScanSnifferCallback()` (line ~6626), OUI table with suspicion levels
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/bacon.cpp` vendor IE OUI `50:52:4B`

### Auth Flood (`HG_FLAG_AUTH_FLOOD`)

Counts authentication frames (subtype `0x0B`). Count >= `HG_AUTH_FLOOD_THRESHOLD` (20) per 10s triggers the flag. Retaliates with `SSIDS_AUTH_FLOOD[]`.

**Reference implementations:**
- **M5PORKCHOP** — [0ct0sec/M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP): `src/modes/oink.cpp` active PMKID extraction via association requests, EAPOL M1 KDE pattern `DD 14 00 0F AC 04`

### Cross-detector Correlation

Logs correlated attack patterns:
- **Deauth + Evil Twin** = active AP attack
- **Probe Flood + Karma** = karma attack in progress
- **Pwnagotchi + Deauth** = pwnagotchi actively hunting

## Hardware

Target: M5Stack AtomS3 (ESP32-S3). Console is via USB JTAG (native USB), not UART. Partition table gives 3MB for the factory app.
