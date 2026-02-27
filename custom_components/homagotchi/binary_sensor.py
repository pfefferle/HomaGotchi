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

from .const import (
    BLE_SIGNATURES,
    CONF_AUTO_RESET_TIMEOUT,
    CONF_INTENSITY_THRESHOLD,
    CONF_INTENSITY_WINDOW,
    DEFAULT_AUTO_RESET_TIMEOUT,
    DEFAULT_INTENSITY_THRESHOLD,
    DEFAULT_INTENSITY_WINDOW,
    DOMAIN,
)
from .signatures import match_ble_signatures

_LOGGER = logging.getLogger(__name__)


class BleSpamActivitySensor(BinarySensorEntity):
    """General BLE spam/pentest signature activity sensor."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:bluetooth-alert"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the BLE spam activity sensor."""
        self.hass = hass
        self._entry = entry
        self._attr_name = "BLE Spam Activity"
        self._attr_unique_id = f"{DOMAIN}_ble_spam_detector"
        self._attr_is_on = False
        self._attr_device_class = BinarySensorDeviceClass.PROBLEM

        self._intensity_threshold = entry.options.get(
            CONF_INTENSITY_THRESHOLD, DEFAULT_INTENSITY_THRESHOLD
        )
        self._intensity_window = entry.options.get(
            CONF_INTENSITY_WINDOW, DEFAULT_INTENSITY_WINDOW
        )
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
            model="BLE Signature Detector",
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

        matches = match_ble_signatures(service_info, time_since_last_seen)
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

        self.async_write_ha_state()

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

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return rich state attributes for automations and debugging."""
        devices: list[dict[str, Any]] = []
        for device in self._devices.values():
            devices.append(
                {
                    "address": device["address"],
                    "name": device["name"],
                    "rssi": device["rssi"],
                    "first_seen": device["first_seen"].isoformat(),
                    "last_seen": device["last_seen"].isoformat(),
                    "count": device["count"],
                    "signatures": sorted(device["signatures"]),
                    "signature_counts": dict(device["signature_counts"]),
                    "last_details": dict(device["last_details"]),
                }
            )

        return {
            "detection_active": self._attr_is_on,
            "detector_type": "spam_activity",
            "scanner_source": "home_assistant_bluetooth",
            "total_signature_matches": self._total_matches,
            "unique_devices": len(self._devices),
            "last_detection_time": (
                self._last_detection_time.isoformat()
                if self._last_detection_time
                else None
            ),
            "intensity": {
                "current": self._calculate_intensity(datetime.now()),
                "threshold": self._intensity_threshold,
                "window_seconds": self._intensity_window,
            },
            "signature_counts": dict(self._signature_counts),
            "signature_catalog": dict(BLE_SIGNATURES),
            "devices": devices,
        }


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up BLE binary sensors from a config entry."""
    async_add_entities([BleSpamActivitySensor(hass, entry)])
    _LOGGER.info("Configured BLE defensive signature spam detector")
