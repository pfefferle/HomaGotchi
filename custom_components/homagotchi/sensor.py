"""Fun gamification sensors for HomaGotchi."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging

from homeassistant.components.sensor import SensorEntity
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
    STATE_FRIEND_COUNT,
    STATE_FRIEND_ENCOUNTERS,
    STATE_LAST_INCIDENT,
    STATE_STARTED_AT,
    STATE_TOTAL_XP,
    XP_LEVELS,
)

_LOGGER = logging.getLogger(__name__)

# Binary sensor entity IDs to watch for XP / streak events.
_WATCHED_SENSORS = [
    f"binary_sensor.{DOMAIN}_ble_spam",
    f"binary_sensor.{DOMAIN}_pentest",
    f"binary_sensor.{DOMAIN}_deauth",
    f"binary_sensor.{DOMAIN}_evil_twin",
    f"binary_sensor.{DOMAIN}_pwnagotchi",
    f"binary_sensor.{DOMAIN}_beacon_spam",
    f"binary_sensor.{DOMAIN}_probe_flood",
    f"binary_sensor.{DOMAIN}_karma",
    f"binary_sensor.{DOMAIN}_pineapple",
]

_PWNAGOTCHI_SENSOR = f"binary_sensor.{DOMAIN}_pwnagotchi"


def _format_duration(seconds: int) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    remaining_min = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_min}m"
    days = hours // 24
    remaining_hours = hours % 24
    return f"{days}d {remaining_hours}h"


def _level_for_xp(xp: int) -> tuple[str, int | None]:
    """Return (level_name, next_threshold) for a given XP value."""
    level_name = XP_LEVELS[0][1]
    next_threshold = None
    for i, (threshold, name) in enumerate(XP_LEVELS):
        if xp >= threshold:
            level_name = name
            if i + 1 < len(XP_LEVELS):
                next_threshold = XP_LEVELS[i + 1][0]
            else:
                next_threshold = None
    return level_name, next_threshold


class ExperienceLevelSensor(SensorEntity):
    """Tracks total detections as XP and assigns a level."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:star-rising"
    _attr_name = "Experience Level"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_xp_level"
        self._cancel_listener = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Gamification",
        )

    @property
    def _state(self) -> dict:
        return self.hass.data[DOMAIN]["state"]

    @property
    def native_value(self) -> str:
        level_name, _ = _level_for_xp(self._state[STATE_TOTAL_XP])
        return level_name

    @property
    def extra_state_attributes(self) -> dict:
        xp = self._state[STATE_TOTAL_XP]
        level_name, next_at = _level_for_xp(xp)
        attrs = {"xp": xp, "level": level_name}
        if next_at is not None:
            attrs["next_level_at"] = next_at
            attrs["detections_to_next"] = next_at - xp
        return attrs

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = async_track_state_change_event(
            self.hass, _WATCHED_SENSORS, self._on_detection,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_listener is not None:
            self._cancel_listener()
            self._cancel_listener = None

    @callback
    def _on_detection(self, event: Event) -> None:
        new_state = event.data.get("new_state")
        if new_state is None or new_state.state != "on":
            return
        self._state[STATE_TOTAL_XP] += 1
        self.async_write_ha_state()


class FriendsMetSensor(SensorEntity):
    """Counts pwnagotchi friend encounters."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:ghost"
    _attr_name = "Friends Met"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_friends_met"
        self._cancel_listener = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Gamification",
        )

    @property
    def _state(self) -> dict:
        return self.hass.data[DOMAIN]["state"]

    @property
    def native_value(self) -> int:
        return self._state[STATE_FRIEND_COUNT]

    @property
    def extra_state_attributes(self) -> dict:
        encounters = self._state[STATE_FRIEND_ENCOUNTERS]
        attrs = {"encounters": len(encounters)}
        if encounters:
            attrs["last_encounter"] = encounters[-1]
        return attrs

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = async_track_state_change_event(
            self.hass, [_PWNAGOTCHI_SENSOR], self._on_pwnagotchi,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_listener is not None:
            self._cancel_listener()
            self._cancel_listener = None

    @callback
    def _on_pwnagotchi(self, event: Event) -> None:
        new_state = event.data.get("new_state")
        if new_state is None or new_state.state != "on":
            return
        now = datetime.now().isoformat()
        self._state[STATE_FRIEND_COUNT] += 1
        self._state[STATE_FRIEND_ENCOUNTERS].append(now)
        self.async_write_ha_state()


class UptimeSensor(SensorEntity):
    """Shows how long the homagotchi has been running."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:timer-outline"
    _attr_name = "Age"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_uptime"
        self._cancel_timer = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Gamification",
        )

    @property
    def _state(self) -> dict:
        return self.hass.data[DOMAIN]["state"]

    @property
    def native_value(self) -> str:
        started = self._state[STATE_STARTED_AT]
        elapsed = int((datetime.now() - started).total_seconds())
        return _format_duration(elapsed)

    @property
    def extra_state_attributes(self) -> dict:
        started = self._state[STATE_STARTED_AT]
        elapsed = int((datetime.now() - started).total_seconds())
        return {
            "started_at": started.isoformat(),
            "uptime_seconds": elapsed,
        }

    async def async_added_to_hass(self) -> None:
        self._cancel_timer = async_track_time_interval(
            self.hass, self._update, timedelta(seconds=60),
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._cancel_timer is not None:
            self._cancel_timer()
            self._cancel_timer = None

    @callback
    def _update(self, now: object = None) -> None:
        self.async_write_ha_state()


class EventStreakSensor(SensorEntity):
    """Tracks time since the last detection incident."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:shield-check"
    _attr_name = "Time Without Incident"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_streak"
        self._cancel_listener = None
        self._cancel_timer = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Gamification",
        )

    @property
    def _state(self) -> dict:
        return self.hass.data[DOMAIN]["state"]

    def _any_sensor_active(self) -> bool:
        """Return True if any watched binary sensor is currently on."""
        for entity_id in _WATCHED_SENSORS:
            state = self.hass.states.get(entity_id)
            if state is not None and state.state == "on":
                return True
        return False

    def _streak_seconds(self) -> int:
        if self._any_sensor_active():
            return 0
        last = self._state[STATE_LAST_INCIDENT]
        ref = last if last is not None else self._state[STATE_STARTED_AT]
        return int((datetime.now() - ref).total_seconds())

    @property
    def native_value(self) -> str:
        return _format_duration(self._streak_seconds())

    @property
    def extra_state_attributes(self) -> dict:
        last = self._state[STATE_LAST_INCIDENT]
        return {
            "last_incident": last.isoformat() if last else None,
            "streak_seconds": self._streak_seconds(),
        }

    async def async_added_to_hass(self) -> None:
        self._cancel_listener = async_track_state_change_event(
            self.hass, _WATCHED_SENSORS, self._on_detection,
        )
        self._cancel_timer = async_track_time_interval(
            self.hass, self._update, timedelta(seconds=60),
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
        new_state = event.data.get("new_state")
        if new_state is None or new_state.state != "on":
            return
        self._state[STATE_LAST_INCIDENT] = datetime.now()
        self.async_write_ha_state()

    @callback
    def _update(self, now: object = None) -> None:
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up gamification sensors."""
    async_add_entities([
        ExperienceLevelSensor(hass, entry),
        FriendsMetSensor(hass, entry),
        UptimeSensor(hass, entry),
        EventStreakSensor(hass, entry),
    ])
    _LOGGER.info("Configured gamification sensors")
