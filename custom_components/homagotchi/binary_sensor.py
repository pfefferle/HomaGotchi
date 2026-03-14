"""Defensive BLE binary sensors for HomaGotchi."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.bluetooth import (
    BluetoothScanningMode,
    BluetoothServiceInfo,
    async_get_scanner,
    async_register_callback,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from .bthome import (
    BTHOME_SERVICE_UUID,
    parse_bthome_v2,
)
from .const import (
    BLE_SIGNATURES,
    CONF_AUTO_RESET_TIMEOUT,
    CONF_INTENSITY_THRESHOLD,
    CONF_INTENSITY_WINDOW,
    CONF_WIFI_DEAUTH_THRESHOLD,
    DEFAULT_AUTO_RESET_TIMEOUT,
    DEFAULT_INTENSITY_THRESHOLD,
    DEFAULT_INTENSITY_WINDOW,
    DEFAULT_WIFI_DEAUTH_THRESHOLD,
    DOMAIN,
    EVENT_DETECTION,
    FLAG_ASSOC_FLOOD,
    FLAG_AUTH_FLOOD,
    FLAG_BEACON_SPAM,
    FLAG_DEAUTH,
    FLAG_EAPOL_LOGOFF,
    FLAG_EVIL_TWIN,
    FLAG_KARMA,
    FLAG_PINEAPPLE,
    FLAG_PROBE_FLOOD,
    FLAG_PWNAGOTCHI,
    FLAG_RETALIATION,
    FLAG_RTS_CTS,
    FLAG_SAE_FLOOD,
    WIFI_MONITOR_NAME_PREFIX,
)
from .signatures import SignatureMatch, match_ble_signatures

_LOGGER = logging.getLogger(__name__)


class _BaseBleActivitySensor(BinarySensorEntity):
    """Shared BLE signature activity sensor logic."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:bluetooth-searching"
    _signature_families: set[str] | None = None
    _unrecorded_attributes = frozenset({
        "signature_catalog",
        "signature_counts",
        "devices",
        "intensity",
    })

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        name: str,
        unique_id: str,
        model: str,
        device_class: BinarySensorDeviceClass,
        intensity_threshold: int,
        intensity_window: int,
        detector_type: str,
    ) -> None:
        """Initialize a BLE signature activity sensor."""
        self.hass = hass
        self._entry = entry
        self._attr_name = name
        self._attr_unique_id = unique_id
        self._attr_is_on = False
        self._attr_device_class = device_class
        self._detector_type = detector_type

        self._intensity_threshold = intensity_threshold
        self._intensity_window = intensity_window
        self._auto_reset_timeout = entry.options.get(
            CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
        )

        self._callback_unsub = None
        self._reset_timer_unsub = None
        self._last_seen_by_address: dict[str, datetime] = {}

        self._events: list[tuple[datetime, str, str]] = []
        self._total_matches = 0
        self._last_detection_time: datetime | None = None
        self._signature_counts: dict[str, int] = {}
        self._devices: dict[str, dict[str, Any]] = {}

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model=model,
        )

    async def async_added_to_hass(self) -> None:
        """Register Bluetooth callbacks against Home Assistant BLE scanners."""
        scanner = async_get_scanner(self.hass)
        if scanner is None:
            _LOGGER.error(
                "Bluetooth scanner is unavailable; cannot start '%s'",
                self._attr_name,
            )
            return

        self._callback_unsub = async_register_callback(
            self.hass,
            self._handle_bluetooth_advertisement,
            {},
            BluetoothScanningMode.ACTIVE,
        )
        self._reset_timer_unsub = async_track_time_interval(
            self.hass,
            self._check_auto_reset,
            timedelta(seconds=10),
        )
        _LOGGER.info("Started BLE signature monitoring: %s", self._attr_name)

    async def async_will_remove_from_hass(self) -> None:
        """Unregister callbacks and timers."""
        if self._callback_unsub is not None:
            self._callback_unsub()
            self._callback_unsub = None
        if self._reset_timer_unsub is not None:
            self._reset_timer_unsub()
            self._reset_timer_unsub = None

    @callback
    def _handle_bluetooth_advertisement(
        self, service_info: BluetoothServiceInfo, change: Any
    ) -> None:
        """Inspect BLE advertisements and update detector state."""
        del change

        address = service_info.address or "unknown"
        now = datetime.now()

        last_seen = self._last_seen_by_address.get(address)
        time_since_last_seen = (
            (now - last_seen).total_seconds() if last_seen is not None else None
        )
        self._last_seen_by_address[address] = now

        matches = self._filter_matches(
            match_ble_signatures(service_info, time_since_last_seen)
        )
        if not matches:
            return

        for signature_id, _ in matches:
            self._events.append((now, address, signature_id))

        intensity = self._calculate_intensity(now)
        if not self._attr_is_on and intensity < self._intensity_threshold:
            _LOGGER.debug(
                "Suspicious BLE signature(s) observed by '%s': %s (intensity=%d/%d)",
                self._attr_name,
                [signature_id for signature_id, _ in matches],
                intensity,
                self._intensity_threshold,
            )
            return

        self._last_detection_time = now
        self._total_matches += len(matches)

        device = self._devices.setdefault(
            address,
            {
                "address": address,
                "name": service_info.name or "Unknown",
                "first_seen": now,
                "last_seen": now,
                "rssi": service_info.rssi,
                "count": 0,
                "signatures": set(),
                "signature_counts": {},
                "last_details": {},
            },
        )
        device["name"] = service_info.name or device["name"]
        device["last_seen"] = now
        device["rssi"] = service_info.rssi
        device["count"] += len(matches)

        for signature_id, details in matches:
            self._signature_counts[signature_id] = (
                self._signature_counts.get(signature_id, 0) + 1
            )
            device["signatures"].add(signature_id)
            device["signature_counts"][signature_id] = (
                device["signature_counts"].get(signature_id, 0) + 1
            )
            device["last_details"][signature_id] = details

        if not self._attr_is_on and intensity >= self._intensity_threshold:
            self._attr_is_on = True
            _LOGGER.warning(
                "'%s' triggered by BLE signature activity: intensity=%d/%d",
                self._attr_name,
                intensity,
                self._intensity_threshold,
            )

        self.hass.bus.async_fire(EVENT_DETECTION, {
            "detector": self._detector_type,
            "is_on": self._attr_is_on,
        })
        self.async_write_ha_state()

    def _filter_matches(self, matches: list[SignatureMatch]) -> list[SignatureMatch]:
        """Filter signatures by family when configured."""
        if self._signature_families is None:
            return matches

        filtered: list[SignatureMatch] = []
        for signature_id, details in matches:
            family = BLE_SIGNATURES.get(signature_id, {}).get("family")
            if family in self._signature_families:
                filtered.append((signature_id, details))
        return filtered

    def _signature_catalog(self) -> dict[str, dict[str, Any]]:
        """Return signature metadata relevant to this sensor."""
        if self._signature_families is None:
            return dict(BLE_SIGNATURES)

        return {
            signature_id: details
            for signature_id, details in BLE_SIGNATURES.items()
            if details.get("family") in self._signature_families
        }

    @callback
    def _check_auto_reset(self, now: datetime) -> None:
        """Automatically reset the sensor after inactivity."""
        del now

        if not self._attr_is_on or self._last_detection_time is None:
            return

        idle_for = (datetime.now() - self._last_detection_time).total_seconds()
        if idle_for <= self._auto_reset_timeout:
            return

        _LOGGER.info(
            "Auto-resetting '%s' after %.0fs without new signatures",
            self._attr_name,
            idle_for,
        )
        self._reset_detection_state()
        self.hass.bus.async_fire(EVENT_DETECTION, {
            "detector": self._detector_type,
            "is_on": False,
        })
        self.async_write_ha_state()

    def _reset_detection_state(self) -> None:
        """Reset rolling detection state after timeout."""
        self._attr_is_on = False
        self._events.clear()
        self._total_matches = 0
        self._last_detection_time = None
        self._signature_counts.clear()
        self._devices.clear()

    def _calculate_intensity(self, now: datetime) -> int:
        """Calculate rolling event intensity within the configured window."""
        cutoff = now - timedelta(seconds=self._intensity_window)
        self._events = [event for event in self._events if event[0] > cutoff]
        return len(self._events)

    def _describe_signature(self, signature_id: str) -> str:
        """Return a human-readable label for a signature ID."""
        meta = BLE_SIGNATURES.get(signature_id, {})
        return meta.get("description", signature_id.replace("_", " ").title())

    def _build_summary(self) -> str:
        """Build a one-line human-readable summary of current detections."""
        if not self._attr_is_on:
            return "No activity"

        # Collect unique attack descriptions across all devices
        attack_types: list[str] = []
        for sig_id in self._signature_counts:
            label = self._describe_signature(sig_id)
            if label not in attack_types:
                attack_types.append(label)

        device_names = [
            d.get("name", d["address"]) for d in self._devices.values()
        ]

        parts: list[str] = []
        if attack_types:
            parts.append(", ".join(attack_types[:3]))
            if len(attack_types) > 3:
                parts.append(f"(+{len(attack_types) - 3} more)")
        if device_names:
            parts.append(f"from {', '.join(device_names[:3])}")
            if len(device_names) > 3:
                parts.append(f"(+{len(device_names) - 3} more)")

        return " ".join(parts) if parts else "Suspicious activity detected"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return state attributes with human-readable summaries."""
        # Readable attack list: "AppleJuice popup (x3), FlipperZero (x1)"
        attacks: list[str] = []
        for sig_id, count in self._signature_counts.items():
            label = self._describe_signature(sig_id)
            attacks.append(f"{label} (x{count})" if count > 1 else label)

        # Readable device list: "FlipperBLE (AA:BB:CC, -42 dBm)"
        devices: list[str] = []
        devices_detail: list[dict[str, Any]] = []
        for device in self._devices.values():
            name = device.get("name", device["address"])
            rssi = device["rssi"]
            addr = device["address"]
            devices.append(f"{name} ({addr}, {rssi} dBm)")
            devices_detail.append(
                {
                    "address": addr,
                    "name": name,
                    "rssi": rssi,
                    "first_seen": device["first_seen"].isoformat(),
                    "last_seen": device["last_seen"].isoformat(),
                    "hits": device["count"],
                    "signatures": sorted(device["signatures"]),
                    "signature_counts": dict(device["signature_counts"]),
                    "last_details": dict(device["last_details"]),
                }
            )

        return {
            "summary": self._build_summary(),
            "attacks": attacks,
            "detected_devices": devices,
            "total_hits": self._total_matches,
            "device_count": len(self._devices),
            "last_seen": (
                self._last_detection_time.isoformat()
                if self._last_detection_time
                else None
            ),
            # Unrecorded detail attributes (for developer tools / debugging)
            "intensity": {
                "current": self._calculate_intensity(datetime.now()),
                "threshold": self._intensity_threshold,
                "window_seconds": self._intensity_window,
            },
            "signature_counts": dict(self._signature_counts),
            "signature_catalog": self._signature_catalog(),
            "devices": devices_detail,
        }


class BleSpamActivitySensor(_BaseBleActivitySensor):
    """General BLE spam/pentest signature activity sensor."""

    _attr_icon = "mdi:bluetooth-alert"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the BLE spam activity sensor."""
        super().__init__(
            hass,
            entry,
            name="BLE Spam Activity",
            unique_id=f"{DOMAIN}_ble_spam",
            model="BLE Signature Detector",
            device_class=BinarySensorDeviceClass.PROBLEM,
            intensity_threshold=entry.options.get(
                CONF_INTENSITY_THRESHOLD, DEFAULT_INTENSITY_THRESHOLD
            ),
            intensity_window=entry.options.get(
                CONF_INTENSITY_WINDOW, DEFAULT_INTENSITY_WINDOW
            ),
            detector_type="spam_activity",
        )


class BlePentestPresenceSensor(_BaseBleActivitySensor):
    """Presence sensor for concrete pentest-device signatures."""

    _attr_icon = "mdi:access-point"
    _signature_families = {"flipper_zero", "bruce"}

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the pentest presence sensor."""
        super().__init__(
            hass,
            entry,
            name="Pentest Device Presence",
            unique_id=f"{DOMAIN}_pentest",
            model="BLE Presence Detector",
            device_class=BinarySensorDeviceClass.PRESENCE,
            intensity_threshold=1,
            intensity_window=entry.options.get(
                CONF_INTENSITY_WINDOW, DEFAULT_INTENSITY_WINDOW
            ),
            detector_type="presence",
        )


class CompanionWifiSensor(BinarySensorEntity):
    """Base class for WiFi sensors fed by BTHome companion devices.

    The companion firmware sends four ordered count_u16 objects:
      [0] deauth frame count
      [1] disassoc frame count
      [2] probe request count
      [3] flags bitmask (HG_FLAG_* bits from config.h / const.py)
    Subclasses set ``_flag_mask`` to select which flag bit(s) they monitor.
    """

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _flag_mask: int = 0
    _unrecorded_attributes = frozenset({
        "companion_devices",
    })

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        name: str,
        unique_id: str,
        icon: str,
    ) -> None:
        """Initialize a companion WiFi sensor."""
        self.hass = hass
        self._entry = entry
        self._attr_name = name
        self._attr_unique_id = unique_id
        self._attr_icon = icon
        self._attr_is_on = False

        self._auto_reset_timeout = entry.options.get(
            CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
        )
        self._deauth_threshold = entry.options.get(
            CONF_WIFI_DEAUTH_THRESHOLD, DEFAULT_WIFI_DEAUTH_THRESHOLD
        )

        self._callback_unsub = None
        self._reset_timer_unsub = None
        self._last_detection_time: datetime | None = None
        self._total_deauth: int = 0
        self._total_disassoc: int = 0
        self._companion_devices: dict[str, dict[str, Any]] = {}

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="WiFi Monitor",
        )

    async def async_added_to_hass(self) -> None:
        """Register BLE callback for BTHome WiFi monitor devices."""
        scanner = async_get_scanner(self.hass)
        if scanner is None:
            _LOGGER.error("Bluetooth scanner unavailable; %s disabled", self._attr_name)
            return

        self._callback_unsub = async_register_callback(
            self.hass,
            self._handle_ble_advertisement,
            {},
            BluetoothScanningMode.ACTIVE,
        )
        self._reset_timer_unsub = async_track_time_interval(
            self.hass,
            self._check_auto_reset,
            timedelta(seconds=10),
        )

    async def async_will_remove_from_hass(self) -> None:
        """Clean up callbacks."""
        if self._callback_unsub is not None:
            self._callback_unsub()
            self._callback_unsub = None
        if self._reset_timer_unsub is not None:
            self._reset_timer_unsub()
            self._reset_timer_unsub = None

    @callback
    def _handle_ble_advertisement(
        self, service_info: BluetoothServiceInfo, change: Any
    ) -> None:
        """Parse BTHome advertisements from companion devices."""
        del change

        name = service_info.name or ""
        if not name.startswith(WIFI_MONITOR_NAME_PREFIX):
            return

        service_data = service_info.service_data or {}
        raw: bytes | None = None
        for uuid_str, payload in service_data.items():
            if BTHOME_SERVICE_UUID in str(uuid_str).lower():
                raw = bytes(payload) if not isinstance(payload, bytes) else payload
                break

        if raw is None:
            return

        parsed = parse_bthome_v2(raw)
        if parsed is None:
            return

        address = service_info.address or "unknown"
        prev_id = self._companion_devices.get(address, {}).get("packet_id")
        if parsed.packet_id is not None and parsed.packet_id == prev_id:
            return

        counts = parsed.get_all("count")
        deauth = counts[0] if len(counts) > 0 else 0
        disassoc = counts[1] if len(counts) > 1 else 0
        probes = counts[2] if len(counts) > 2 else 0
        flags = counts[3] if len(counts) > 3 else 0
        flag = bool(flags & self._flag_mask)

        now = datetime.now()

        device = self._companion_devices.setdefault(address, {
            "address": address,
            "name": name,
            "first_seen": now,
        })
        device["name"] = name
        device["last_seen"] = now
        device["rssi"] = service_info.rssi
        device["packet_id"] = parsed.packet_id
        device["last_deauth"] = deauth
        device["last_disassoc"] = disassoc
        device["last_probes"] = probes
        device["last_flags"] = flags

        self._total_deauth += deauth
        self._total_disassoc += disassoc

        triggered = self._evaluate(flag, deauth, disassoc)

        if triggered and not self._attr_is_on:
            self._attr_is_on = True
            self._last_detection_time = now
            _LOGGER.warning("'%s' triggered (from %s)", self._attr_name, name)
            self.hass.bus.async_fire(EVENT_DETECTION, {
                "detector": self._attr_unique_id,
                "is_on": True,
            })
            self.async_write_ha_state()
        elif triggered:
            self._last_detection_time = now
            self.async_write_ha_state()

    def _evaluate(self, flag: int, deauth: int, disassoc: int) -> bool:
        """Decide whether this report should trigger the sensor."""
        return bool(flag)

    @callback
    def _check_auto_reset(self, now: datetime) -> None:
        """Reset sensor after inactivity."""
        del now

        if not self._attr_is_on or self._last_detection_time is None:
            return

        idle = (datetime.now() - self._last_detection_time).total_seconds()
        if idle <= self._auto_reset_timeout:
            return

        _LOGGER.info("'%s' auto-reset after %.0fs idle", self._attr_name, idle)
        self._attr_is_on = False
        self._total_deauth = 0
        self._total_disassoc = 0
        self._last_detection_time = None
        self.hass.bus.async_fire(EVENT_DETECTION, {
            "detector": self._attr_unique_id,
            "is_on": False,
        })
        self.async_write_ha_state()

    def _build_summary(self) -> str:
        """Build a human-readable summary for the current state."""
        if not self._attr_is_on:
            return "No activity"
        return "Active"  # Subclasses override for specifics

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return companion WiFi detection attributes."""
        reporters = [
            f"{d['name']} ({d['address']}, {d.get('rssi', '?')} dBm)"
            for d in self._companion_devices.values()
        ]

        companions = [
            {
                "address": d["address"],
                "name": d["name"],
                "rssi": d.get("rssi"),
                "last_seen": d["last_seen"].isoformat() if d.get("last_seen") else None,
                "last_deauth": d.get("last_deauth", 0),
                "last_disassoc": d.get("last_disassoc", 0),
                "last_probes": d.get("last_probes", 0),
                "last_flags": d.get("last_flags", 0),
            }
            for d in self._companion_devices.values()
        ]

        return {
            "summary": self._build_summary(),
            "deauth_frames": self._total_deauth,
            "disassoc_frames": self._total_disassoc,
            "reporters": reporters,
            "last_seen": (
                self._last_detection_time.isoformat()
                if self._last_detection_time
                else None
            ),
            # Unrecorded detail
            "companion_devices": companions,
        }


class WifiDeauthSensor(CompanionWifiSensor):
    """WiFi deauthentication / disassociation attack sensor."""

    _flag_mask = FLAG_DEAUTH

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the deauth sensor."""
        super().__init__(
            hass, entry,
            name="WiFi Deauth Attack",
            unique_id=f"{DOMAIN}_deauth",
            icon="mdi:wifi-alert",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No deauth activity"
        total = self._total_deauth + self._total_disassoc
        parts = []
        if self._total_deauth:
            parts.append(f"{self._total_deauth} deauth")
        if self._total_disassoc:
            parts.append(f"{self._total_disassoc} disassoc")
        return f"Attack detected: {' + '.join(parts)} frames"


class WifiPwnagotchiSensor(CompanionWifiSensor):
    """Pwnagotchi presence sensor via WiFi beacon analysis."""

    _flag_mask = FLAG_PWNAGOTCHI

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the pwnagotchi sensor."""
        super().__init__(
            hass, entry,
            name="Pwnagotchi Detected",
            unique_id=f"{DOMAIN}_pwnagotchi",
            icon="mdi:ghost",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No pwnagotchi nearby"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Pwnagotchi beacon detected (via {', '.join(reporters[:2])})"


class WifiEvilTwinSensor(CompanionWifiSensor):
    """Evil twin AP detection sensor."""

    _flag_mask = FLAG_EVIL_TWIN

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the evil twin sensor."""
        super().__init__(
            hass, entry,
            name="Evil Twin Detected",
            unique_id=f"{DOMAIN}_evil_twin",
            icon="mdi:access-point-network-off",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No rogue APs detected"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Duplicate SSID from different BSSID (via {', '.join(reporters[:2])})"


class WifiBeaconSpamSensor(CompanionWifiSensor):
    """Beacon spam / fake AP flood detection sensor."""

    _flag_mask = FLAG_BEACON_SPAM

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the beacon spam sensor."""
        super().__init__(
            hass, entry,
            name="Beacon Spam Detected",
            unique_id=f"{DOMAIN}_beacon_spam",
            icon="mdi:wifi-strength-1-alert",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No beacon spam"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Beacon flood from many unique MACs (via {', '.join(reporters[:2])})"


class WifiProbeFloodSensor(CompanionWifiSensor):
    """Probe request flood detection sensor."""

    _flag_mask = FLAG_PROBE_FLOOD

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the probe flood sensor."""
        super().__init__(
            hass, entry,
            name="Probe Flood Detected",
            unique_id=f"{DOMAIN}_probe_flood",
            icon="mdi:radar",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No probe flood"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"High probe request rate detected (via {', '.join(reporters[:2])})"


class WifiKarmaSensor(CompanionWifiSensor):
    """Karma / multi-SSID device detection sensor."""

    _flag_mask = FLAG_KARMA

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the karma sensor."""
        super().__init__(
            hass, entry,
            name="Karma Attack Detected",
            unique_id=f"{DOMAIN}_karma",
            icon="mdi:access-point-network",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No karma devices"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Single BSSID advertising multiple SSIDs (via {', '.join(reporters[:2])})"


class WifiPineappleSensor(CompanionWifiSensor):
    """WiFi Pineapple / suspicious device OUI detection sensor."""

    _flag_mask = FLAG_PINEAPPLE

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the pineapple sensor."""
        super().__init__(
            hass, entry,
            name="Pineapple Detected",
            unique_id=f"{DOMAIN}_pineapple",
            icon="mdi:fruit-pineapple",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No pineapple devices"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Suspicious OUI (Hak5/Alfa) in beacon (via {', '.join(reporters[:2])})"


class WifiAuthFloodSensor(CompanionWifiSensor):
    """Authentication frame flood detection sensor."""

    _flag_mask = FLAG_AUTH_FLOOD

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the auth flood sensor."""
        super().__init__(
            hass, entry,
            name="Auth Flood Detected",
            unique_id=f"{DOMAIN}_auth_flood",
            icon="mdi:shield-lock-open",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No auth flood"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"High auth frame rate detected (via {', '.join(reporters[:2])})"


class WifiAssocFloodSensor(CompanionWifiSensor):
    """Association request flood detection sensor."""

    _flag_mask = FLAG_ASSOC_FLOOD

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the assoc flood sensor."""
        super().__init__(
            hass, entry,
            name="Assoc Flood Detected",
            unique_id=f"{DOMAIN}_assoc_flood",
            icon="mdi:shield-lock-open",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No assoc flood"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"High association request rate (via {', '.join(reporters[:2])})"


class WifiEapolLogoffSensor(CompanionWifiSensor):
    """EAPOL-Logoff attack detection sensor."""

    _flag_mask = FLAG_EAPOL_LOGOFF

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the EAPOL logoff sensor."""
        super().__init__(
            hass, entry,
            name="EAPOL Logoff Attack",
            unique_id=f"{DOMAIN}_eapol_logoff",
            icon="mdi:lock-alert",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No EAPOL logoff attacks"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"EAPOL logoff frames detected (via {', '.join(reporters[:2])})"


class WifiRtsCtsAttackSensor(CompanionWifiSensor):
    """RTS/CTS channel reservation attack detection sensor."""

    _flag_mask = FLAG_RTS_CTS

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the RTS/CTS attack sensor."""
        super().__init__(
            hass, entry,
            name="RTS/CTS Attack Detected",
            unique_id=f"{DOMAIN}_rts_cts",
            icon="mdi:wifi-strength-off",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No RTS/CTS attacks"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"CTS frames with large NAV values (via {', '.join(reporters[:2])})"


class WifiSaeFloodSensor(CompanionWifiSensor):
    """SAE commit flood (WPA3 Dragonblood) detection sensor."""

    _flag_mask = FLAG_SAE_FLOOD

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the SAE flood sensor."""
        super().__init__(
            hass, entry,
            name="SAE Flood Detected",
            unique_id=f"{DOMAIN}_sae_flood",
            icon="mdi:shield-alert",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "No SAE flood"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"WPA3 SAE commit flood (via {', '.join(reporters[:2])})"


class WifiRetaliationSensor(CompanionWifiSensor):
    """Indicates when the companion device is retaliating with defensive beacons."""

    _flag_mask = FLAG_RETALIATION
    _attr_device_class = None  # informational, not a problem

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the retaliation sensor."""
        super().__init__(
            hass, entry,
            name="Retaliation Active",
            unique_id=f"{DOMAIN}_retaliation",
            icon="mdi:sword-cross",
        )

    def _build_summary(self) -> str:
        if not self._attr_is_on:
            return "Standing down"
        reporters = [d["name"] for d in self._companion_devices.values()]
        return f"Broadcasting defensive beacons (via {', '.join(reporters[:2])})"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensors from a config entry."""
    async_add_entities(
        [
            BleSpamActivitySensor(hass, entry),
            BlePentestPresenceSensor(hass, entry),
            WifiDeauthSensor(hass, entry),
            WifiPwnagotchiSensor(hass, entry),
            WifiEvilTwinSensor(hass, entry),
            WifiBeaconSpamSensor(hass, entry),
            WifiProbeFloodSensor(hass, entry),
            WifiKarmaSensor(hass, entry),
            WifiPineappleSensor(hass, entry),
            WifiAuthFloodSensor(hass, entry),
            WifiAssocFloodSensor(hass, entry),
            WifiEapolLogoffSensor(hass, entry),
            WifiRtsCtsAttackSensor(hass, entry),
            WifiSaeFloodSensor(hass, entry),
            WifiRetaliationSensor(hass, entry),
        ]
    )
    _LOGGER.info("Configured defensive signature sensors")
