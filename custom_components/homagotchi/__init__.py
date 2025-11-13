from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.typing import ConfigType
from homeassistant import config_entries
from homeassistant.helpers import entity_registry as er
import voluptuous as vol
import logging

from .const import DOMAIN, FACES
from .config_flow import HomaGotchiConfigFlow

_LOGGER = logging.getLogger(__name__)

SET_FACE_SCHEMA = vol.Schema({
    vol.Required("face_index"): vol.All(vol.Coerce(int), vol.Range(min=0, max=len(FACES) - 1)),
})

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the HomaGotchi component."""
    hass.data.setdefault(DOMAIN, {})

    async def set_face(call: ServiceCall) -> None:
        """Service to set the face by index."""
        face_index = call.data.get("face_index")

        # Get entity registry
        entity_reg = er.async_get(hass)
        face_entity_id = f"text.{DOMAIN}_face"

        # Find the entity
        entity_entry = entity_reg.async_get(face_entity_id)
        if not entity_entry:
            _LOGGER.error("Face entity not found: %s", face_entity_id)
            return

        # Try to get the entity from the component
        try:
            component = hass.data.get("entity_components", {}).get("text")
            if component:
                entity = component.get_entity(face_entity_id)
                if entity and hasattr(entity, "set_face"):
                    entity.set_face(face_index)
                    _LOGGER.debug("Face set to index %d", face_index)
                else:
                    _LOGGER.error("Could not access set_face method on entity")
            else:
                _LOGGER.error("Text component not found")
        except Exception as e:
            _LOGGER.error("Error setting face: %s", str(e))

    # Register the service
    hass.services.async_register(
        DOMAIN,
        "set_face",
        set_face,
        schema=SET_FACE_SCHEMA,
    )

    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up HomaGotchi from a config entry."""
    hass.data[DOMAIN][entry.entry_id] = entry.data

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    # Forward the setup to the sensor, binary_sensor, and text platforms
    await hass.config_entries.async_forward_entry_setups(entry, ["binary_sensor", "text"])
    return True

async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update options."""
    await hass.config_entries.async_reload(entry.entry_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Unload the sensor, binary_sensor, and text platforms
    await hass.config_entries.async_unload_platforms(entry, ["binary_sensor", "text"])
    hass.data[DOMAIN].pop(entry.entry_id)
    return True

# Register the config flow
config_entries.HANDLERS.register(DOMAIN)(HomaGotchiConfigFlow)
