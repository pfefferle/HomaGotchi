"""Config flow for HomaGotchi."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import HANDLERS, ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
import voluptuous as vol

from .const import (
    CONF_AUTO_RESET_TIMEOUT,
    CONF_INTENSITY_THRESHOLD,
    CONF_INTENSITY_WINDOW,
    CONF_WIFI_DEAUTH_THRESHOLD,
    DEFAULT_AUTO_RESET_TIMEOUT,
    DEFAULT_INTENSITY_THRESHOLD,
    DEFAULT_INTENSITY_WINDOW,
    DEFAULT_WIFI_DEAUTH_THRESHOLD,
    DOMAIN,
)


class HomaGotchiConfigFlow(ConfigFlow):
    """Handle a config flow for HomaGotchi."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return HomaGotchiOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step."""
        if user_input is not None:
            return self.async_create_entry(
                title="HomaGotchi",
                data={},
                options={
                    CONF_INTENSITY_THRESHOLD: DEFAULT_INTENSITY_THRESHOLD,
                    CONF_INTENSITY_WINDOW: DEFAULT_INTENSITY_WINDOW,
                    CONF_AUTO_RESET_TIMEOUT: DEFAULT_AUTO_RESET_TIMEOUT,
                    CONF_WIFI_DEAUTH_THRESHOLD: DEFAULT_WIFI_DEAUTH_THRESHOLD,
                },
            )

        return self.async_show_form(step_id="user")


class HomaGotchiOptionsFlow(OptionsFlow):
    """Handle options flow for HomaGotchi."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_INTENSITY_THRESHOLD,
                        default=self.config_entry.options.get(
                            CONF_INTENSITY_THRESHOLD,
                            DEFAULT_INTENSITY_THRESHOLD,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=20)),
                    vol.Optional(
                        CONF_INTENSITY_WINDOW,
                        default=self.config_entry.options.get(
                            CONF_INTENSITY_WINDOW,
                            DEFAULT_INTENSITY_WINDOW,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=5, max=120)),
                    vol.Optional(
                        CONF_AUTO_RESET_TIMEOUT,
                        default=self.config_entry.options.get(
                            CONF_AUTO_RESET_TIMEOUT,
                            DEFAULT_AUTO_RESET_TIMEOUT,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=10, max=600)),
                    vol.Optional(
                        CONF_WIFI_DEAUTH_THRESHOLD,
                        default=self.config_entry.options.get(
                            CONF_WIFI_DEAUTH_THRESHOLD,
                            DEFAULT_WIFI_DEAUTH_THRESHOLD,
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=100)),
                }
            ),
        )


# Compatibility registration for Home Assistant versions with different
# ConfigFlow handler registration behavior.
HANDLERS.register(DOMAIN)(HomaGotchiConfigFlow)
