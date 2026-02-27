# AGENTS.md

## Mission

Keep HomaGotchi as a defensive BLE monitoring integration for Home Assistant.

## Non-Negotiable Scope

- BLE-only detection using Home Assistant Bluetooth APIs.
- Defensive signature detection and alerting only.
- No offensive tooling, packet injection, jamming, deauth, or exploit helpers.
- No WiFi monitor-mode detection features in this repository.

## Preferred Sensor Semantics

- Use `binary_sensor` entities with `presence`-style behavior to represent
  observed suspicious BLE signature activity.
- Keep thresholds and reset timers configurable through config flow options.

## Coding Rules

- Favor maintainable, testable detection logic over large monolithic handlers.
- Keep signature metadata centralized in `custom_components/homagotchi/const.py`.
- Keep detector logic in `custom_components/homagotchi/binary_sensor.py`.
- Preserve Home Assistant native patterns for async callbacks and unload cleanup.

## Documentation Rules

- README must describe BLE-only defensive scope.
- Any docs mentioning WiFi deauth, offensive use, or attack execution are out of scope.
- If scope changes, update README and translation strings in the same PR.

## Release Hygiene

- Update `manifest.json` version when behavior/scope changes.
- Ensure config flow labels match the current options and sensor semantics.
