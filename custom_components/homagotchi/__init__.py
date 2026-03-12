"""HomaGotchi integration setup."""

from __future__ import annotations

from datetime import datetime

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType

from .const import (
    DOMAIN,
    STATE_FRIEND_COUNT,
    STATE_FRIEND_ENCOUNTERS,
    STATE_LAST_INCIDENT,
    STATE_STARTED_AT,
    STATE_TOTAL_XP,
)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.DEVICE_TRACKER,
    Platform.SENSOR,
    Platform.TEXT,
]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the HomaGotchi component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up HomaGotchi from a config entry."""
    hass.data[DOMAIN][entry.entry_id] = entry.options
    hass.data[DOMAIN].setdefault("state", {
        STATE_TOTAL_XP: 0,
        STATE_FRIEND_COUNT: 0,
        STATE_FRIEND_ENCOUNTERS: [],
        STATE_STARTED_AT: datetime.now(),
        STATE_LAST_INCIDENT: None,
    })
    entry.async_on_unload(entry.add_update_listener(async_update_options))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the integration when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
