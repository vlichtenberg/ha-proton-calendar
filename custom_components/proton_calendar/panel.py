"""Show or hide Home Assistant's Calendar panel in the sidebar."""

from __future__ import annotations

from homeassistant.components import frontend
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant, callback

from .const import CONF_SHOW_SIDEBAR_PANEL, DEFAULT_SHOW_SIDEBAR_PANEL, DOMAIN

PANEL = "calendar"


@callback
def async_update_sidebar_panel(
    hass: HomeAssistant,
    *,
    setting_up: ConfigEntry | None = None,
    unloading: ConfigEntry | None = None,
) -> None:
    """Hide the Calendar panel while any active Proton entry asks for it.

    The panel belongs to the calendar integration and is shared by all calendars and
    users, so it is only restored when no Proton entry wants it hidden.
    """
    active = [
        entry
        for entry in hass.config_entries.async_entries(DOMAIN)
        if entry is setting_up
        or (entry is not unloading and entry.state is ConfigEntryState.LOADED)
    ]
    hide = any(
        not entry.options.get(CONF_SHOW_SIDEBAR_PANEL, DEFAULT_SHOW_SIDEBAR_PANEL)
        for entry in active
    )
    exists = frontend.async_panel_exists(hass, PANEL)
    if hide and exists:
        frontend.async_remove_panel(hass, PANEL)
    elif not hide and not exists and "calendar" in hass.config.components:
        # Same registration as homeassistant.components.calendar.
        frontend.async_register_built_in_panel(hass, PANEL, "calendar", "mdi:calendar")
