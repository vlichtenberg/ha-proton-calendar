"""The Proton Calendar integration."""

from __future__ import annotations

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_SESSION
from .coordinator import ProtonCalendarConfigEntry, ProtonCalendarCoordinator
from .panel import async_update_sidebar_panel
from .proton import ProtonClient, Session

PLATFORMS: list[Platform] = [Platform.CALENDAR]


def create_client(hass: HomeAssistant, session: Session | None = None) -> ProtonClient:
    """Create a Proton client that runs CPU-heavy crypto in the executor."""
    return ProtonClient(
        async_get_clientsession(hass),
        session=session,
        executor=hass.async_add_executor_job,
    )


async def async_setup_entry(hass: HomeAssistant, entry: ProtonCalendarConfigEntry) -> bool:
    """Set up Proton Calendar from a config entry."""
    session_data = entry.data.get(CONF_SESSION)
    if not session_data or not session_data.get("key_passphrase"):
        raise ConfigEntryAuthFailed("No stored Proton session")

    client = create_client(hass, Session.from_dict(session_data))
    coordinator = ProtonCalendarCoordinator(hass, entry, client)
    client.on_session_update = coordinator.async_persist_session

    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    async_update_sidebar_panel(hass, setting_up=entry)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ProtonCalendarConfigEntry) -> None:
    """Reload when the calendar selection or polling options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ProtonCalendarConfigEntry) -> bool:
    """Unload a config entry."""
    if unloaded := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        async_update_sidebar_panel(hass, unloading=entry)
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ProtonCalendarConfigEntry) -> None:
    """Revoke the Proton session when the integration is removed."""
    session_data = entry.data.get(CONF_SESSION)
    if session_data:
        await create_client(hass, Session.from_dict(session_data)).logout()
