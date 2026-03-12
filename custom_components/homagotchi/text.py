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
from homeassistant.helpers.event import (
    async_track_state_change_event,
    async_track_time_interval,
)

from .const import (
    DOMAIN,
    FACE_ALERT_BLE_SPAM,
    FACE_ALERT_DEAUTH,
    FACE_ALERT_EVIL_TWIN,
    FACE_ALERT_FLIPPER,
    FACE_ALERT_MULTI,
    FACE_ALERT_PWNAGOTCHI,
    FACE_IDLE,
    FACE_MONITORING,
    PWNAGOTCHI_FACES,
    QUIP_MAP,
    QUIPS_IDLE,
    QUIPS_MULTI,
)

_LOGGER = logging.getLogger(__name__)

# Entity IDs of the binary sensors both text entities react to.
_SENSOR_MOOD_MAP = {
    f"binary_sensor.{DOMAIN}_ble_spam": FACE_ALERT_BLE_SPAM,
    f"binary_sensor.{DOMAIN}_pentest": FACE_ALERT_FLIPPER,
    f"binary_sensor.{DOMAIN}_deauth": FACE_ALERT_DEAUTH,
    f"binary_sensor.{DOMAIN}_evil_twin": FACE_ALERT_EVIL_TWIN,
    f"binary_sensor.{DOMAIN}_pwnagotchi": FACE_ALERT_PWNAGOTCHI,
    f"binary_sensor.{DOMAIN}_beacon_spam": FACE_ALERT_BLE_SPAM,
    f"binary_sensor.{DOMAIN}_probe_flood": FACE_ALERT_BLE_SPAM,
    f"binary_sensor.{DOMAIN}_karma": FACE_ALERT_EVIL_TWIN,
    f"binary_sensor.{DOMAIN}_pineapple": FACE_ALERT_FLIPPER,
}


def _suffix_from_entity_id(entity_id: str) -> str:
    """Extract the sensor suffix from a full entity ID."""
    prefix = f"binary_sensor.{DOMAIN}_"
    if entity_id.startswith(prefix):
        return entity_id[len(prefix):]
    return ""


class _ActiveSensorMixin:
    """Shared helper for checking active binary sensors."""

    hass: HomeAssistant

    def _get_active_sensors(self) -> list[str]:
        """Return entity IDs of sensors currently in 'on' state."""
        active = []
        for entity_id in _SENSOR_MOOD_MAP:
            state = self.hass.states.get(entity_id)
            if state is not None and state.state == "on":
                active.append(entity_id)
        return active


class PwnagotchiFaceText(_ActiveSensorMixin, TextEntity):
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

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Status Text",
        )

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = async_track_state_change_event(
            self.hass,
            list(_SENSOR_MOOD_MAP.keys()),
            self._on_sensor_change,
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
    def _on_sensor_change(self, event: Event) -> None:
        self._manual_override = False
        active = self._get_active_sensors()

        if not active:
            self._attr_native_value = self._pick_face(FACE_MONITORING)
        elif len(active) >= 3:
            self._attr_native_value = self._pick_face(FACE_ALERT_MULTI)
        else:
            entity_id = event.data.get("entity_id", active[0])
            indices = _SENSOR_MOOD_MAP.get(entity_id, FACE_ALERT_BLE_SPAM)
            self._attr_native_value = self._pick_face(indices)

        self.async_write_ha_state()

    @callback
    def _idle_rotate(self, now: object = None) -> None:
        del now
        if self._manual_override:
            return

        active = self._get_active_sensors()
        if not active:
            self._attr_native_value = self._pick_face(FACE_IDLE)
        elif len(active) >= 3:
            self._attr_native_value = self._pick_face(FACE_ALERT_MULTI)
        else:
            entity_id = random.choice(active)
            indices = _SENSOR_MOOD_MAP.get(entity_id, FACE_ALERT_BLE_SPAM)
            self._attr_native_value = self._pick_face(indices)

        self.async_write_ha_state()

    def set_value(self, value: str) -> None:
        self._attr_native_value = value[: self._attr_native_max]
        self._manual_override = True
        self.async_write_ha_state()


class PwnagotchiQuipText(_ActiveSensorMixin, TextEntity):
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

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Status Text",
        )

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = async_track_state_change_event(
            self.hass,
            list(_SENSOR_MOOD_MAP.keys()),
            self._on_sensor_change,
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
    def _on_sensor_change(self, event: Event) -> None:
        self._manual_override = False
        active = self._get_active_sensors()

        if not active:
            self._attr_native_value = random.choice(QUIPS_IDLE)
        elif len(active) >= 3:
            self._attr_native_value = random.choice(QUIPS_MULTI)
        else:
            entity_id = event.data.get("entity_id", active[0])
            suffix = _suffix_from_entity_id(entity_id)
            quips = QUIP_MAP.get(suffix, QUIPS_IDLE)
            self._attr_native_value = random.choice(quips)

        self.async_write_ha_state()

    @callback
    def _idle_rotate(self, now: object = None) -> None:
        del now
        if self._manual_override:
            return

        active = self._get_active_sensors()
        if not active:
            self._attr_native_value = random.choice(QUIPS_IDLE)
        elif len(active) >= 3:
            self._attr_native_value = random.choice(QUIPS_MULTI)
        else:
            entity_id = random.choice(active)
            suffix = _suffix_from_entity_id(entity_id)
            quips = QUIP_MAP.get(suffix, QUIPS_IDLE)
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
