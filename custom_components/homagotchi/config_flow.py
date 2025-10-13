from homeassistant.config_entries import ConfigFlow
from .const import DOMAIN

class HomaGotchiConfigFlow(ConfigFlow):
    """Handle a config flow for HomaGotchi."""

    VERSION = 1
    DOMAIN = DOMAIN

    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="HomaGotchi", data={})
        return self.async_show_form(step_id="user")
