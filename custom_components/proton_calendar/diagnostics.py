"""Diagnostics support for Proton Calendar."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import CONF_SESSION
from .coordinator import ProtonCalendarConfigEntry

TO_REDACT = {CONF_USERNAME, CONF_SESSION, "email", "title", "unique_id"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ProtonCalendarConfigEntry
) -> dict[str, Any]:
    """Return diagnostics without secrets or event contents."""
    coordinator = entry.runtime_data
    data = coordinator.data
    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "app_version": coordinator.client.app_version,
        "calendars": [
            {
                "id": calendar.id,
                "type": calendar.type,
                "flags": calendar.flags,
                "selected": calendar.id in coordinator.selected_ids,
                "cached_occurrences": len(data.events.get(calendar.id, [])) if data else 0,
            }
            for calendar in coordinator.all_calendars.values()
        ],
        "window": {
            "start": data.window_start.isoformat() if data else None,
            "end": data.window_end.isoformat() if data else None,
        },
        "last_update_success": coordinator.last_update_success,
    }
