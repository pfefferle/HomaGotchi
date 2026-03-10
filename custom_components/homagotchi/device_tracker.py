"""BLE signature-backed device trackers for HomaGotchi."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components.bluetooth import (
    BluetoothScanningMode,
    BluetoothServiceInfo,
    async_get_scanner,
    async_register_callback,
)
from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from .const import BLE_SIGNATURES, CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
from .signatures import SignatureMatch, match_ble_signatures

_LOGGER = logging.getLogger(__name__)


class PentestBleDeviceTracker(ScannerEntity):
    """Track a BLE device that matches pentest-related signatures."""

    _attr_has_entity_name = True
    _attr_source_type = SourceType.BLUETOOTH_LE
    _unrecorded_attributes = frozenset({
        "signature_catalog",
        "signature_counts",
        "last_details",
    })

    def __init__(self, address: str, auto_reset_timeout: int) -> None:
        """Initialize a tracked BLE signature device."""
        self._address = address
        self._attr_name = f"Pentest Device {address}"
        self._attr_mac_address = address

        self._auto_reset_timeout = auto_reset_timeout
        self._is_connected = False
        self._last_seen: datetime | None = None
        self._first_seen: datetime | None = None
        self._total_matches = 0
        self._signature_counts: dict[str, int] = {}
        self._last_details: dict[str, dict[str, Any]] = {}
        self._last_rssi: int | None = None

    @property
    def icon(self) -> str:
        """Return an icon that reflects current connection state."""
        return "mdi:bluetooth-connect" if self.is_connected else "mdi:bluetooth-off"

    @property
    def is_connected(self) -> bool:
        """Return whether this tracker is currently active."""
        return self._is_connected

    def apply_matches(
        self,
        now: datetime,
        service_info: BluetoothServiceInfo,
        matches: list[SignatureMatch],
    ) -> None:
        """Apply signature matches from an advertisement."""
        if self._first_seen is None:
            self._first_seen = now

        self._last_seen = now
        self._last_rssi = service_info.rssi
        self._is_connected = True

        if service_info.name:
            self._attr_hostname = service_info.name

        self._total_matches += len(matches)
        for signature_id, details in matches:
            self._signature_counts[signature_id] = (
                self._signature_counts.get(signature_id, 0) + 1
            )
            self._last_details[signature_id] = details

    def refresh_connection_state(self, now: datetime) -> bool:
        """Refresh connected state based on inactivity timeout."""
        if self._last_seen is None:
            return False

        connected = (now - self._last_seen).total_seconds() <= self._auto_reset_timeout
        if connected == self._is_connected:
            return False

        self._is_connected = connected
        return True

    def _describe_signature(self, signature_id: str) -> str:
        """Return a human-readable label for a signature ID."""
        meta = BLE_SIGNATURES.get(signature_id, {})
        return meta.get("description", signature_id.replace("_", " ").title())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return tracker metadata with human-readable summaries."""
        # "FlipperZero BLE service UUID (x3), FlipperZero payload (x1)"
        attacks: list[str] = []
        for sig_id, count in self._signature_counts.items():
            label = self._describe_signature(sig_id)
            attacks.append(f"{label} (x{count})" if count > 1 else label)

        summary = ", ".join(attacks) if attacks else "Unknown device"

        return {
            "summary": summary,
            "attacks": attacks,
            "rssi": self._last_rssi,
            "total_hits": self._total_matches,
            "first_seen": self._first_seen.isoformat() if self._first_seen else None,
            "last_seen": self._last_seen.isoformat() if self._last_seen else None,
            # Unrecorded detail
            "signature_counts": dict(self._signature_counts),
            "last_details": dict(self._last_details),
            "signature_catalog": {
                signature_id: BLE_SIGNATURES[signature_id]
                for signature_id in self._signature_counts
                if signature_id in BLE_SIGNATURES
            },
        }


class PentestBleTrackerManager:
    """Manage dynamic BLE pentest tracker entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        """Initialize manager."""
        self.hass = hass
        self._async_add_entities = async_add_entities
        self._auto_reset_timeout = entry.options.get(
            CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
        )

        self._last_seen_by_address: dict[str, datetime] = {}
        self._trackers: dict[str, PentestBleDeviceTracker] = {}
        self._callback_unsub = None
        self._refresh_unsub = None

    @callback
    def async_start(self) -> None:
        """Start BLE callbacks and state refresh timers."""
        scanner = async_get_scanner(self.hass)
        if scanner is None:
            _LOGGER.error("Bluetooth scanner is unavailable; cannot start device trackers")
            return

        self._callback_unsub = async_register_callback(
            self.hass,
            self._handle_bluetooth_advertisement,
            {},
            BluetoothScanningMode.ACTIVE,
        )
        self._refresh_unsub = async_track_time_interval(
            self.hass,
            self._refresh_tracker_states,
            timedelta(seconds=10),
        )
        _LOGGER.info("Started BLE pentest device tracking")

    @callback
    def async_stop(self) -> None:
        """Stop callbacks and timers."""
        if self._callback_unsub is not None:
            self._callback_unsub()
            self._callback_unsub = None
        if self._refresh_unsub is not None:
            self._refresh_unsub()
            self._refresh_unsub = None

    @callback
    def _handle_bluetooth_advertisement(
        self, service_info: BluetoothServiceInfo, change: Any
    ) -> None:
        """Create/update trackers from matching BLE signatures."""
        del change

        if not service_info.address:
            return

        address = service_info.address.upper()
        now = datetime.now()

        last_seen = self._last_seen_by_address.get(address)
        time_since_last_seen = (
            (now - last_seen).total_seconds() if last_seen is not None else None
        )
        self._last_seen_by_address[address] = now

        matches = self._flipper_matches(
            match_ble_signatures(service_info, time_since_last_seen)
        )
        if not matches:
            return

        tracker = self._trackers.get(address)
        if tracker is None:
            tracker = PentestBleDeviceTracker(address, self._auto_reset_timeout)
            tracker.apply_matches(now, service_info, matches)
            self._trackers[address] = tracker
            self._async_add_entities([tracker])
            return

        tracker.apply_matches(now, service_info, matches)
        tracker.async_write_ha_state()

    @callback
    def _refresh_tracker_states(self, now: datetime) -> None:
        """Auto-reset tracker state after inactivity."""
        current = datetime.now()
        del now

        for tracker in self._trackers.values():
            if tracker.refresh_connection_state(current):
                tracker.async_write_ha_state()

    @staticmethod
    def _flipper_matches(matches: list[SignatureMatch]) -> list[SignatureMatch]:
        """Return matches that represent concrete pentest devices."""
        filtered: list[SignatureMatch] = []
        for signature_id, details in matches:
            family = BLE_SIGNATURES.get(signature_id, {}).get("family")
            if family == "flipper_zero":
                filtered.append((signature_id, details))
        return filtered


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up BLE pentest device trackers."""
    manager = PentestBleTrackerManager(hass, entry, async_add_entities)
    manager.async_start()
    entry.async_on_unload(manager.async_stop)
