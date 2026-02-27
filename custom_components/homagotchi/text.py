"""Pwnagotchi text entity for HomaGotchi."""

from __future__ import annotations

from datetime import timedelta
import logging
import random

from homeassistant.components.text import TextEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN, PWNAGOTCHI_FACES

_LOGGER = logging.getLogger(__name__)


class PwnagotchiFaceText(TextEntity):
    """Simple rotating text face for the shared Pwnagotchi device."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:emoticon-outline"
    _attr_name = "Face"
    _attr_native_min = 0
    _attr_native_max = 64

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the Pwnagotchi face text entity."""
        self.hass = hass
        self._attr_unique_id = f"{DOMAIN}_face"
        self._attr_native_value = PWNAGOTCHI_FACES[0]
        self._cancel_timer = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Pwnagotchi BLE Defense",
            manufacturer="Pwnagotchi",
            model="Status Text",
        )

    async def async_added_to_hass(self) -> None:
        """Rotate faces periodically while the entity is active."""
        self._cancel_timer = async_track_time_interval(
            self.hass,
            self._rotate_face,
            timedelta(seconds=30),
        )

    async def async_will_remove_from_hass(self) -> None:
        """Clean up timers when removed."""
        if self._cancel_timer is not None:
            self._cancel_timer()
            self._cancel_timer = None

    @callback
    def _rotate_face(self, now: object = None) -> None:
        """Set a random ASCII face."""
        del now

        self._attr_native_value = random.choice(PWNAGOTCHI_FACES)
        self.async_write_ha_state()

    def set_value(self, value: str) -> None:
        """Allow manual face override from the UI."""
        self._attr_native_value = value[: self._attr_native_max]
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Pwnagotchi text entities."""
    async_add_entities([PwnagotchiFaceText(hass, entry)])
    _LOGGER.info("Configured Pwnagotchi face text entity")
