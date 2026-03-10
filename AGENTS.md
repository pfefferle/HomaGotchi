# AGENTS.md

## Mission

Keep HomaGotchi as a defensive BLE monitoring integration for Home Assistant.

## Non-Negotiable Scope

- Defensive detection and alerting only.
- BLE signature detection using Home Assistant Bluetooth APIs.
- WiFi deauth/disassoc detection via BTHome companion devices (ESP32 firmware in `firmware/`).
- No offensive tooling, packet injection, jamming, deauth, or exploit helpers.

## Preferred Sensor Semantics

- Use `binary_sensor` entities with `presence`-style behavior to represent
  observed suspicious BLE signature activity.
- Keep thresholds and reset timers configurable through config flow options.

## Coding Rules

- Favor maintainable, testable detection logic over large monolithic handlers.
- Keep signature metadata centralized in `custom_components/homagotchi/const.py`.
- Keep detector logic in `custom_components/homagotchi/binary_sensor.py`.
- Keep BTHome parsing in `custom_components/homagotchi/bthome.py`.
- Preserve Home Assistant native patterns for async callbacks and unload cleanup.

## Documentation Rules

- README must describe defensive-only scope.
- Document WiFi monitoring as passive detection via BTHome companion devices.
- Any docs mentioning offensive use or attack execution are out of scope.
- If scope changes, update README and translation strings in the same PR.

## Release Hygiene

- Update `manifest.json` version when behavior/scope changes.
- Ensure config flow labels match the current options and sensor semantics.
