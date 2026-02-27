# Changelog

All notable changes to HomaGotchi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-27

### Changed
- Refocused integration to defensive BLE-only monitoring.
- Removed legacy non-BLE code paths and related configuration.
- Simplified to one spam-focused `binary_sensor`.
- Added dynamic `device_tracker` entities for Flipper-family device signatures.
- Restored the Pwnagotchi text entity (`text.face`) with lightweight rotating status text.
- Removed Flipper-specific threshold options no longer needed after tracker split.

### Documentation
- Rewrote README/info docs for BLE defensive scope.
- Added repository `AGENTS.md` guidance to keep future changes aligned.

## [1.0.0] - 2025-10-13

### Added
- Initial release
- ASCII face text entity with 21 different faces
- Automatic face rotation every 30 seconds
- `homagotchi.set_face` service to manually set faces
- BLE spam detector binary sensor
- FlipperZero dedicated detector binary sensor
- Detection of 8 spam types:
  - FlipperZero/ESP32 Marauder (Service UUIDs + manufacturer data)
  - Apple Continuity spam (SourApple attacks)
  - Samsung BLE spam
  - Google Fast Pair spam
  - Microsoft Swift Pair spam
  - Tile tracker spam
  - AirTag spoofing
  - Rapid advertising patterns
- Smart filtering to avoid false positives from legitimate devices
- Rich attributes for all detectors including:
  - Detection counts and types
  - Device information (MAC, RSSI, name)
  - Threat level assessment
  - Color identification for FlipperZero
- Config flow for easy setup
- HACS integration support

### Detection Methods
- Based on [Wall of Flippers](https://github.com/K3YOMI/Wall-of-Flippers) proven detection
- Primary: Service UUID detection (`00003081/82/83-0000-1000-8000-00805F9B34FB`)
- Fallback: Manufacturer data patterns (`0x8130`, `0x8230`, `0x8330`)
- Smart filtering based on:
  - Rapid MAC address changes
  - Device name legitimacy
  - Data pattern analysis

### Technical
- Requires Home Assistant 2024.1.0+
- Depends on built-in Bluetooth integration
- Uses `bleak>=0.20.2` for BLE scanning
- Config flow for easy setup via UI
