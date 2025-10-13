from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.typing import ConfigType
from homeassistant import config_entries
import voluptuous as vol

from .const import DOMAIN, FACES
from .config_flow import HomaGotchiConfigFlow

SET_FACE_SCHEMA = vol.Schema({
    vol.Required("face_index"): vol.All(vol.Coerce(int), vol.Range(min=0, max=len(FACES) - 1)),
})

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the HomaGotchi component."""
    hass.data.setdefault(DOMAIN, {})

    async def set_face(call: ServiceCall) -> None:
        """Service to set the face by index."""
        face_index = call.data.get("face_index")

        # Find the face text entity
        for entry_id, entry_data in hass.data[DOMAIN].items():
            if isinstance(entry_id, str) and not entry_id.startswith("_"):
                face_entity_id = f"text.{DOMAIN}_face"

                # Get entity from registry
                entity_reg = hass.helpers.entity_registry.async_get(hass)
                entity_entry = entity_reg.async_get(face_entity_id)

                if entity_entry:
                    # Call the entity's set_face method via the platform
                    platform = hass.data["entity_platform"][DOMAIN]["text"]
                    for entity in platform.entities.values():
                        if hasattr(entity, "set_face") and entity.entity_id == face_entity_id:
                            entity.set_face(face_index)
                            break

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

    # Forward the setup to the sensor, binary_sensor, and text platforms
    await hass.config_entries.async_forward_entry_setups(entry, ["binary_sensor", "text"])
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Unload the sensor, binary_sensor, and text platforms
    await hass.config_entries.async_unload_platforms(entry, ["binary_sensor", "text"])
    hass.data[DOMAIN].pop(entry.entry_id)
    return True

# Register the config flow
config_entries.HANDLERS.register(DOMAIN)(HomaGotchiConfigFlow)
