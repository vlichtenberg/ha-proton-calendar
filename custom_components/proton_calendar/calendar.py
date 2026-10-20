"""Calendar entities for Proton Calendar."""

from __future__ import annotations

from datetime import datetime

from homeassistant.components.calendar import CalendarEntity, CalendarEvent
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import ProtonCalendarConfigEntry, ProtonCalendarCoordinator
from .proton import Occurrence

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ProtonCalendarConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one calendar entity per selected Proton calendar."""
    coordinator = entry.runtime_data
    async_add_entities(
        ProtonCalendarEntity(coordinator, calendar_id) for calendar_id in coordinator.data.calendars
    )


def _to_event(occurrence: Occurrence) -> CalendarEvent:
    start = occurrence.start
    end = occurrence.end
    if isinstance(start, datetime):
        start = dt_util.as_local(start)
    if isinstance(end, datetime):
        end = dt_util.as_local(end)
    return CalendarEvent(
        start=start,
        end=end,
        summary=occurrence.summary,
        description=occurrence.description,
        location=occurrence.location,
        uid=occurrence.uid or None,
        recurrence_id=occurrence.recurrence_id,
        rrule=occurrence.rrule,
    )


class ProtonCalendarEntity(CoordinatorEntity[ProtonCalendarCoordinator], CalendarEntity):
    """A single (decrypted) Proton calendar."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: ProtonCalendarCoordinator, calendar_id: str) -> None:
        super().__init__(coordinator)
        self._calendar_id = calendar_id
        calendar = coordinator.data.calendars[calendar_id]
        account = coordinator.config_entry.unique_id or coordinator.config_entry.entry_id
        self._attr_unique_id = f"{account}_{calendar_id}"
        self._attr_name = calendar.name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, account)},
            name=f"Proton Calendar ({coordinator.config_entry.title})",
            manufacturer="Proton AG",
            model="Proton Calendar",
            entry_type=DeviceEntryType.SERVICE,
            configuration_url="https://calendar.proton.me",
        )

    @property
    def event(self) -> CalendarEvent | None:
        """The current or next upcoming event, evaluated at the time of reading."""
        now = dt_util.now()
        tz = dt_util.get_default_time_zone()
        for occurrence in self.coordinator.data.events.get(self._calendar_id, []):
            if occurrence.end_datetime(tz) > now:
                return _to_event(occurrence)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        calendar = self.coordinator.data.calendars.get(self._calendar_id)
        return {"color": calendar.color} if calendar else {}

    async def async_get_events(
        self, hass: HomeAssistant, start_date: datetime, end_date: datetime
    ) -> list[CalendarEvent]:
        """Events in a time range, for the calendar panel and calendar triggers."""
        occurrences = await self.coordinator.async_get_occurrences(
            self._calendar_id, start_date, end_date
        )
        return [_to_event(o) for o in occurrences]
