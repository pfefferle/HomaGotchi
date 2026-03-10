"""BTHome v2 payload parser for HomaGotchi WiFi monitor devices."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# BTHome v2 object definitions (ID -> name, size in bytes)
_OBJECT_DEFS: dict[int, tuple[str, int]] = {
    0x00: ("packet_id", 1),    # uint8
    0x0F: ("generic_boolean", 1),  # uint8
    0x3D: ("count", 2),        # uint16
}

BTHOME_SERVICE_UUID = "0000fcd2-0000-1000-8000-00805f9b34fb"
BTHOME_SERVICE_UUID_SHORT = "FCD2"


@dataclass
class BTHomePayload:
    """Parsed BTHome v2 advertisement payload."""

    version: int = 2
    encrypted: bool = False
    trigger_based: bool = False
    packet_id: int | None = None
    objects: list[tuple[str, Any]] = field(default_factory=list)

    def get_all(self, name: str) -> list[Any]:
        """Return all values for a given object name, in order."""
        return [value for obj_name, value in self.objects if obj_name == name]

    def get_first(self, name: str, default: Any = None) -> Any:
        """Return the first value for a given object name."""
        for obj_name, value in self.objects:
            if obj_name == name:
                return value
        return default


def parse_bthome_v2(data: bytes) -> BTHomePayload | None:
    """Parse a BTHome v2 service data payload.

    The payload starts with a device info byte followed by object entries.
    Returns None if the data is not valid BTHome v2.
    """
    if len(data) < 1:
        return None

    device_info = data[0]
    version = 2 if (device_info & 0xE0) == 0x40 else 1
    if version != 2:
        return None

    payload = BTHomePayload(
        version=2,
        encrypted=bool(device_info & 0x01),
        trigger_based=bool(device_info & 0x04),
    )

    if payload.encrypted:
        return payload  # Encrypted payloads need decryption first

    pos = 1
    while pos < len(data):
        obj_id = data[pos]
        pos += 1

        obj_def = _OBJECT_DEFS.get(obj_id)
        if obj_def is None:
            break  # Unknown object, stop parsing

        name, size = obj_def
        if pos + size > len(data):
            break

        if size == 1:
            value = data[pos]
        elif size == 2:
            value = data[pos] | (data[pos + 1] << 8)
        elif size == 4:
            value = (
                data[pos]
                | (data[pos + 1] << 8)
                | (data[pos + 2] << 16)
                | (data[pos + 3] << 24)
            )
        else:
            value = data[pos : pos + size]

        if name == "packet_id":
            payload.packet_id = value
        else:
            payload.objects.append((name, value))

        pos += size

    return payload
