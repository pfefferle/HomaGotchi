"""BLE signature matching helpers."""

from __future__ import annotations

from typing import Any

from homeassistant.components.bluetooth import BluetoothServiceInfo

from .const import (
    AIRTAG_PREFIX,
    AIRTAG_RAPID_INTERVAL,
    APPLE_CUSTOM_CRASH_PREFIX,
    APPLE_COMPANY_ID,
    APPLE_CONTINUITY_PREFIXES,
    APPLE_JUICE_CORE,
    APPLE_JUICE_PREFIX,
    APPLE_POPUP_CORE,
    APPLE_POPUP_PREFIX,
    APPLE_SETUP_PREFIX,
    BRUCE_NAME_PREFIXES,
    BRUCE_SERVICE_UUIDS,
    CATHACK_SERVICE_UUIDS,
    FLIPPER_PAYLOAD_PATTERNS,
    FLIPPER_SERVICE_UUIDS,
    GOOGLE_FAST_PAIR_MARKER,
    GOOGLE_FAST_PAIR_PAYLOAD_TAIL,
    LIGHTBLUE_SERVICE_UUID,
    MAX_AIRTAG_MINIMAL_PAYLOAD_LENGTH,
    MICROSOFT_COMPANY_ID,
    MICROSOFT_SWIFT_PAIR_PAYLOAD_PREFIX,
    RAPID_ADVERTISEMENT_INTERVAL,
    SAMSUNG_COMPANY_ID,
    SAMSUNG_BUDS_PAYLOAD_PREFIX,
    SAMSUNG_WATCH_PAYLOAD_PREFIX,
    SOURAPPLE_PREFIXES,
    SOURAPPLE_TAIL_MARKER,
    TILE_MARKER,
)

APPLE_NAME_HINTS = {
    "apple",
    "iphone",
    "ipad",
    "airpods",
    "watch",
    "homepod",
    "mac",
    "beats",
}
GOOGLE_NAME_HINTS = {"google", "pixel", "nest"}
MICROSOFT_NAME_HINTS = {"microsoft", "surface", "xbox"}
SAMSUNG_NAME_HINTS = {"samsung", "galaxy"}
TILE_NAME_HINTS = {"tile"}

SignatureMatch = tuple[str, dict[str, Any]]


def _to_bytes(value: Any) -> bytes:
    """Normalize manufacturer/service payload values into bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return b""


def _name_matches_hints(name: str | None, hints: set[str]) -> bool:
    """Return True when a broadcast name looks like the expected vendor device."""
    if not name:
        return False
    lowered = name.lower()
    return any(hint in lowered for hint in hints)


def _markers_from_service_info(service_info: BluetoothServiceInfo) -> list[str]:
    """Extract UUID/service markers used by Fast Pair/Tile style spoof signatures."""
    markers: list[str] = []
    markers.extend(uuid.upper() for uuid in (service_info.service_uuids or []))
    markers.extend(str(key).upper() for key in (service_info.service_data or {}))
    return markers


def match_ble_signatures(
    service_info: BluetoothServiceInfo, time_since_last_seen: float | None
) -> list[SignatureMatch]:
    """Match a BLE advertisement against known pentest/spoofing signatures."""
    matches: list[SignatureMatch] = []
    seen_signatures: set[str] = set()

    def add_match(signature_id: str, details: dict[str, Any]) -> None:
        if signature_id in seen_signatures:
            return
        seen_signatures.add(signature_id)
        matches.append((signature_id, details))

    manufacturer_data = service_info.manufacturer_data or {}
    service_data = service_info.service_data or {}
    service_markers = _markers_from_service_info(service_info)
    rapid_adv = (
        time_since_last_seen is not None
        and time_since_last_seen <= RAPID_ADVERTISEMENT_INTERVAL
    )

    # FlipperZero direct signature (service UUID)
    for service_uuid in service_info.service_uuids or []:
        service_uuid_upper = service_uuid.upper()
        for expected_uuid, color in FLIPPER_SERVICE_UUIDS.items():
            expected_upper = expected_uuid.upper()
            if service_uuid_upper == expected_upper or expected_upper in service_uuid_upper:
                add_match(
                    "flipper_zero_service_uuid",
                    {
                        "service_uuid": service_uuid,
                        "flipper_color": color,
                        "method": "service_uuid",
                    },
                )

    # LightBlue BLE Explorer (recon tool)
    for service_uuid in service_info.service_uuids or []:
        if service_uuid.lower() == LIGHTBLUE_SERVICE_UUID:
            add_match(
                "lightblue_recon",
                {
                    "service_uuid": service_uuid,
                    "method": "service_uuid",
                },
            )

    # CatHack / Apple Juice attack UUIDs
    for service_uuid in service_info.service_uuids or []:
        service_uuid_lower = service_uuid.lower()
        for expected_uuid, variant in CATHACK_SERVICE_UUIDS.items():
            if service_uuid_lower == expected_uuid.lower():
                add_match(
                    "cathack_apple_juice",
                    {
                        "service_uuid": service_uuid,
                        "variant": variant,
                        "method": "service_uuid",
                    },
                )

    # Bruce Firmware — unique service UUIDs
    for service_uuid in service_info.service_uuids or []:
        service_uuid_lower = service_uuid.lower()
        for expected_uuid, variant in BRUCE_SERVICE_UUIDS.items():
            if service_uuid_lower == expected_uuid.lower():
                add_match(
                    "bruce_service_uuid",
                    {
                        "service_uuid": service_uuid,
                        "variant": variant,
                        "method": "service_uuid",
                    },
                )

    # Bruce Firmware — device name pattern matching
    # Bruce advertises as "Bruc", "Bruce-Attack", "Bruce-Exploit",
    # "Bruce-Flooder", "Bruce-Spammer", "BRUCE-PN532-BLE", etc.
    if service_info.name:
        if any(service_info.name.startswith(prefix) for prefix in BRUCE_NAME_PREFIXES):
            add_match(
                "bruce_device_name",
                {
                    "name": service_info.name,
                    "method": "device_name",
                },
            )

    # FlipperZero/ESP32 Marauder payload signatures
    for company_id, payload in manufacturer_data.items():
        payload_bytes = _to_bytes(payload)
        for pattern, color in FLIPPER_PAYLOAD_PATTERNS.items():
            if pattern in payload_bytes:
                add_match(
                    "flipper_zero_payload",
                    {
                        "company_id": hex(company_id),
                        "pattern": pattern.hex(),
                        "flipper_color": color,
                        "method": "manufacturer_data",
                    },
                )

    for company_id, payload in manufacturer_data.items():
        payload_bytes = _to_bytes(payload)
        if not payload_bytes:
            continue

        if company_id == APPLE_COMPANY_ID:
            # AppleJuice popup payload: 07 19 07 [model] 20 75 aa 30
            if (
                payload_bytes.startswith(APPLE_JUICE_PREFIX)
                and len(payload_bytes) >= 8
                and payload_bytes[4:8] == APPLE_JUICE_CORE
            ):
                add_match(
                    "apple_juice_spoofing",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:8].hex(),
                        "method": "manufacturer_data",
                    },
                )

            # Marauder Apple popup payload variant.
            if (
                payload_bytes.startswith(APPLE_POPUP_PREFIX)
                and APPLE_POPUP_CORE in payload_bytes
            ):
                add_match(
                    "apple_popup_spoofing",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:9].hex(),
                        "method": "manufacturer_data",
                    },
                )

            # Apple setup popup payload used by AppleTV/setup spam tooling.
            if payload_bytes.startswith(APPLE_SETUP_PREFIX):
                add_match(
                    "apple_setup_spoofing",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:9].hex(),
                        "method": "manufacturer_data",
                    },
                )

            # SourApple payload shape from public spam tooling.
            if (
                any(payload_bytes.startswith(prefix) for prefix in SOURAPPLE_PREFIXES)
                and len(payload_bytes) >= 10
                and payload_bytes[7:10] == SOURAPPLE_TAIL_MARKER
            ):
                add_match(
                    "sourapple_spoofing",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:10].hex(),
                        "method": "manufacturer_data",
                    },
                )

            # Custom crash payload shape used by newer continuity spam tooling.
            if (
                payload_bytes.startswith(APPLE_CUSTOM_CRASH_PREFIX)
                and len(payload_bytes) >= 10
                and payload_bytes[7:10] == SOURAPPLE_TAIL_MARKER
            ):
                add_match(
                    "apple_custom_crash_spoofing",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:10].hex(),
                        "method": "manufacturer_data",
                    },
                )

            # Broader continuity heuristics for unknown/spoofed variants.
            # Require BOTH rapid advertising AND name mismatch to reduce
            # false positives from legitimate Apple devices.
            if any(payload_bytes.startswith(prefix) for prefix in APPLE_CONTINUITY_PREFIXES):
                if rapid_adv and not _name_matches_hints(service_info.name, APPLE_NAME_HINTS):
                    add_match(
                        "apple_continuity_spoofing",
                        {
                            "company_id": hex(company_id),
                            "payload_prefix": payload_bytes[:2].hex(),
                            "method": "manufacturer_data",
                        },
                    )

            # AirTag spoofing pattern (minimal Find My payload + suspicious timing/name).
            if payload_bytes.startswith(AIRTAG_PREFIX):
                rapid_airtag = (
                    time_since_last_seen is not None
                    and time_since_last_seen <= AIRTAG_RAPID_INTERVAL
                )
                minimal_payload = len(payload_bytes) <= MAX_AIRTAG_MINIMAL_PAYLOAD_LENGTH
                if minimal_payload and (
                    rapid_airtag
                    and not _name_matches_hints(service_info.name, APPLE_NAME_HINTS)
                ):
                    add_match(
                        "airtag_spoofing",
                        {
                            "company_id": hex(company_id),
                            "payload_prefix": payload_bytes[:2].hex(),
                            "method": "manufacturer_data",
                        },
                    )

        if company_id == MICROSOFT_COMPANY_ID:
            if payload_bytes.startswith(MICROSOFT_SWIFT_PAIR_PAYLOAD_PREFIX):
                add_match(
                    "microsoft_swift_pair_payload",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:3].hex(),
                        "method": "manufacturer_data",
                    },
                )
                # Only flag spoofing for Swift Pair payloads (not all Microsoft ads)
                if rapid_adv and not _name_matches_hints(service_info.name, MICROSOFT_NAME_HINTS):
                    add_match(
                        "microsoft_swift_pair_spoofing",
                        {
                            "company_id": hex(company_id),
                            "method": "manufacturer_data",
                        },
                    )

        if company_id == SAMSUNG_COMPANY_ID:
            if payload_bytes.startswith(SAMSUNG_WATCH_PAYLOAD_PREFIX):
                add_match(
                    "samsung_watch_payload",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:10].hex(),
                        "method": "manufacturer_data",
                    },
                )
            if payload_bytes.startswith(SAMSUNG_BUDS_PAYLOAD_PREFIX):
                add_match(
                    "samsung_buds_payload",
                    {
                        "company_id": hex(company_id),
                        "payload_prefix": payload_bytes[:10].hex(),
                        "method": "manufacturer_data",
                    },
                )
            if rapid_adv and not _name_matches_hints(service_info.name, SAMSUNG_NAME_HINTS):
                add_match(
                    "samsung_smarttag_spoofing",
                    {
                        "company_id": hex(company_id),
                        "method": "manufacturer_data",
                    },
                )

    # Parse Fast Pair service-data shape: 3-byte model + 0x02 0x0A + tx-power.
    for uuid_str, payload in service_data.items():
        uuid_upper = str(uuid_str).upper()
        payload_bytes = _to_bytes(payload)
        if GOOGLE_FAST_PAIR_MARKER in uuid_upper and len(payload_bytes) >= 5:
            if payload_bytes[-3:-1] == GOOGLE_FAST_PAIR_PAYLOAD_TAIL:
                add_match(
                    "google_fast_pair_payload",
                    {
                        "service_uuid": str(uuid_str),
                        "payload_tail": payload_bytes[-3:].hex(),
                        "method": "service_data",
                    },
                )

    if any(GOOGLE_FAST_PAIR_MARKER in marker for marker in service_markers) and (
        rapid_adv and not _name_matches_hints(service_info.name, GOOGLE_NAME_HINTS)
    ):
        add_match(
            "google_fast_pair_spoofing",
            {
                "marker": GOOGLE_FAST_PAIR_MARKER,
                "method": "service_marker",
            },
        )

    if any(TILE_MARKER in marker for marker in service_markers) and (
        rapid_adv and not _name_matches_hints(service_info.name, TILE_NAME_HINTS)
    ):
        add_match(
            "tile_spoofing",
            {
                "marker": TILE_MARKER,
                "method": "service_marker",
            },
        )

    return matches
