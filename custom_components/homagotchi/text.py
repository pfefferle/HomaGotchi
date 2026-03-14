"""Pwnagotchi text entities for HomaGotchi."""

from __future__ import annotations

from datetime import timedelta
import logging
import random

from homeassistant.components.text import TextEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    DOMAIN,
    EVENT_DETECTION,
    FACE_ALERT_AUTH_FLOOD,
    FACE_ALERT_BLE_SPAM,
    FACE_ALERT_DEAUTH,
    FACE_ALERT_EVIL_TWIN,
    FACE_ALERT_FLIPPER,
    FACE_ALERT_MULTI,
    FACE_ALERT_PWNAGOTCHI,
    FACE_IDLE,
    FACE_MONITORING,
    PWNAGOTCHI_FACES,
    QUIPS_AUTH_FLOOD,
    QUIPS_BEACON_SPAM,
    QUIPS_BLE_SPAM,
    QUIPS_DEAUTH,
    QUIPS_EVIL_TWIN,
    QUIPS_FLIPPER,
    QUIPS_IDLE,
    QUIPS_KARMA,
    QUIPS_MULTI,
    QUIPS_PINEAPPLE,
    QUIPS_PROBE_FLOOD,
    QUIPS_PWNAGOTCHI,
)

_LOGGER = logging.getLogger(__name__)

# Map detector IDs (from EVENT_DETECTION events) to face mood indices.
_DETECTOR_FACE_MAP: dict[str, list[int]] = {
    "spam_activity": FACE_ALERT_BLE_SPAM,
    "presence": FACE_ALERT_FLIPPER,
    f"{DOMAIN}_deauth": FACE_ALERT_DEAUTH,
    f"{DOMAIN}_evil_twin": FACE_ALERT_EVIL_TWIN,
    f"{DOMAIN}_pwnagotchi": FACE_ALERT_PWNAGOTCHI,
    f"{DOMAIN}_beacon_spam": FACE_ALERT_BLE_SPAM,
    f"{DOMAIN}_probe_flood": FACE_ALERT_BLE_SPAM,
    f"{DOMAIN}_karma": FACE_ALERT_EVIL_TWIN,
    f"{DOMAIN}_pineapple": FACE_ALERT_FLIPPER,
    f"{DOMAIN}_auth_flood": FACE_ALERT_AUTH_FLOOD,
}

# Map detector IDs to quip pools.
_DETECTOR_QUIP_MAP: dict[str, list[str]] = {
    "spam_activity": QUIPS_BLE_SPAM,
    "presence": QUIPS_FLIPPER,
    f"{DOMAIN}_deauth": QUIPS_DEAUTH,
    f"{DOMAIN}_evil_twin": QUIPS_EVIL_TWIN,
    f"{DOMAIN}_pwnagotchi": QUIPS_PWNAGOTCHI,
    f"{DOMAIN}_beacon_spam": QUIPS_BEACON_SPAM,
    f"{DOMAIN}_probe_flood": QUIPS_PROBE_FLOOD,
    f"{DOMAIN}_karma": QUIPS_KARMA,
    f"{DOMAIN}_pineapple": QUIPS_PINEAPPLE,
    f"{DOMAIN}_auth_flood": QUIPS_AUTH_FLOOD,
}


class PwnagotchiFaceText(TextEntity):
    """Reactive text face that reflects current detection state."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:emoticon-outline"
    _attr_name = "Face"
    _attr_native_min = 0
    _attr_native_max = 64

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._attr_unique_id = f"{DOMAIN}_face"
        self._attr_native_value = PWNAGOTCHI_FACES[FACE_IDLE[0]]
        self._cancel_timer = None
        self._cancel_listener = None
        self._manual_override = False
        self._active_detectors: set[str] = set()

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Status Text",
        )

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = self.hass.bus.async_listen(
            EVENT_DETECTION, self._on_detection,
        )
        self._cancel_timer = async_track_time_interval(
            self.hass,
            self._idle_rotate,
            timedelta(seconds=30),
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_listener is not None:
            self._cancel_listener()
            self._cancel_listener = None
        if self._cancel_timer is not None:
            self._cancel_timer()
            self._cancel_timer = None

    def _pick_face(self, indices: list[int]) -> str:
        return PWNAGOTCHI_FACES[random.choice(indices)]

    @callback
    def _on_detection(self, event: Event) -> None:
        detector = event.data.get("detector", "")
        is_on = event.data.get("is_on", False)

        if detector not in _DETECTOR_FACE_MAP:
            return

        if is_on:
            self._active_detectors.add(detector)
        else:
            self._active_detectors.discard(detector)

        self._manual_override = False

        if not self._active_detectors:
            self._attr_native_value = self._pick_face(FACE_MONITORING)
        elif len(self._active_detectors) >= 3:
            self._attr_native_value = self._pick_face(FACE_ALERT_MULTI)
        else:
            indices = _DETECTOR_FACE_MAP.get(detector, FACE_ALERT_BLE_SPAM)
            self._attr_native_value = self._pick_face(indices)

        self.async_write_ha_state()

    @callback
    def _idle_rotate(self, now: object = None) -> None:
        del now
        if self._manual_override:
            return

        if not self._active_detectors:
            self._attr_native_value = self._pick_face(FACE_IDLE)
        elif len(self._active_detectors) >= 3:
            self._attr_native_value = self._pick_face(FACE_ALERT_MULTI)
        else:
            detector = random.choice(list(self._active_detectors))
            indices = _DETECTOR_FACE_MAP.get(detector, FACE_ALERT_BLE_SPAM)
            self._attr_native_value = self._pick_face(indices)

        self.async_write_ha_state()

    def set_value(self, value: str) -> None:
        self._attr_native_value = value[: self._attr_native_max]
        self._manual_override = True
        self.async_write_ha_state()


class PwnagotchiQuipText(TextEntity):
    """Witty status messages reacting to detections."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:message-text-outline"
    _attr_name = "Status"
    _attr_native_min = 0
    _attr_native_max = 128

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._attr_unique_id = f"{DOMAIN}_quip"
        self._attr_native_value = random.choice(QUIPS_IDLE)
        self._cancel_timer = None
        self._cancel_listener = None
        self._manual_override = False
        self._active_detectors: set[str] = set()

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Status Text",
        )

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = self.hass.bus.async_listen(
            EVENT_DETECTION, self._on_detection,
        )
        self._cancel_timer = async_track_time_interval(
            self.hass,
            self._idle_rotate,
            timedelta(seconds=120),
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_listener is not None:
            self._cancel_listener()
            self._cancel_listener = None
        if self._cancel_timer is not None:
            self._cancel_timer()
            self._cancel_timer = None

    @callback
    def _on_detection(self, event: Event) -> None:
        detector = event.data.get("detector", "")
        is_on = event.data.get("is_on", False)

        if detector not in _DETECTOR_QUIP_MAP:
            return

        if is_on:
            self._active_detectors.add(detector)
        else:
            self._active_detectors.discard(detector)

        self._manual_override = False

        if not self._active_detectors:
            self._attr_native_value = random.choice(QUIPS_IDLE)
        elif len(self._active_detectors) >= 3:
            self._attr_native_value = random.choice(QUIPS_MULTI)
        else:
            quips = _DETECTOR_QUIP_MAP.get(detector, QUIPS_IDLE)
            self._attr_native_value = random.choice(quips)

        self.async_write_ha_state()

    @callback
    def _idle_rotate(self, now: object = None) -> None:
        del now
        if self._manual_override:
            return

        if not self._active_detectors:
            self._attr_native_value = random.choice(QUIPS_IDLE)
        elif len(self._active_detectors) >= 3:
            self._attr_native_value = random.choice(QUIPS_MULTI)
        else:
            detector = random.choice(list(self._active_detectors))
            quips = _DETECTOR_QUIP_MAP.get(detector, QUIPS_IDLE)
            self._attr_native_value = random.choice(quips)

        self.async_write_ha_state()

    def set_value(self, value: str) -> None:
        self._attr_native_value = value[: self._attr_native_max]
        self._manual_override = True
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Pwnagotchi text entities."""
    async_add_entities([
        PwnagotchiFaceText(hass, entry),
        PwnagotchiQuipText(hass, entry),
    ])
    _LOGGER.info("Configured Pwnagotchi text entities")
