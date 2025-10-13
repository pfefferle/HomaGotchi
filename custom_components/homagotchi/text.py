"""The HomaGotchi text platform."""
from __future__ import annotations

import logging
import random
from typing import Any
from datetime import timedelta

from homeassistant.components.text import TextEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN, FACES

_LOGGER = logging.getLogger(__name__)


class HomagotchiFaceText(TextEntity):
    """Text entity for Pwnagotchi ASCII face that changes based on mood."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:emoticon-outline"
    _attr_native_min = 0
    _attr_native_max = 50

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the text entity."""
        self.hass = hass
        self._attr_name = "Face"
        self._attr_unique_id = f"{DOMAIN}_face"
        self._attr_native_value = FACES[2]  # awake / normal
        self._cancel_timer = None
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="HomaGotchi",
            manufacturer="HomaGotchi",
            model="Pwnagotchi",
        )

    async def async_added_to_hass(self) -> None:
        """Set up periodic face changes when added to hass."""
        # Change face every 30 seconds
        self._cancel_timer = async_track_time_interval(
            self.hass,
            self._change_face,
            timedelta(seconds=30)
        )

    async def async_will_remove_from_hass(self) -> None:
        """Clean up when removed."""
        if self._cancel_timer:
            self._cancel_timer()

    async def _change_face(self, now=None) -> None:
        """Randomly change the face."""
        self._attr_native_value = random.choice(FACES)
        self.async_write_ha_state()

    def set_face(self, face_index: int) -> None:
        """Set a specific face by index."""
        if 0 <= face_index < len(FACES):
            self._attr_native_value = FACES[face_index]
            self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the text entities from a config entry."""
    entities = [
        HomagotchiFaceText(hass, entry),
    ]
    async_add_entities(entities)
    _LOGGER.info("Pwnagotchi face text entity setup completed")
