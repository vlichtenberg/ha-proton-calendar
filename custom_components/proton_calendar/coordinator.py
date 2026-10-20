"""Data update coordinator for Proton Calendar."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (
    CONF_CALENDARS,
    CONF_FILTERS,
    CONF_LOOKAHEAD_DAYS,
    CONF_SCAN_INTERVAL,
    CONF_SESSION,
    DEFAULT_LOOKAHEAD_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DOMAIN,
    LOOKBEHIND_DAYS,
)
from .proton import (
    Occurrence,
    ProtonAuthError,
    ProtonCalendar,
    ProtonClient,
    ProtonError,
    Session,
    expand_events,
)

_LOGGER = logging.getLogger(__name__)

type ProtonCalendarConfigEntry = ConfigEntry[ProtonCalendarCoordinator]


@dataclass
class CalendarData:
    """Cached occurrences for the selected calendars."""

    window_start: datetime
    window_end: datetime
    calendars: dict[str, ProtonCalendar] = field(default_factory=dict)
    events: dict[str, list[Occurrence]] = field(default_factory=dict)


class ProtonCalendarCoordinator(DataUpdateCoordinator[CalendarData]):
    """Periodically fetches and decrypts events of the selected calendars."""

    config_entry: ProtonCalendarConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: ProtonCalendarConfigEntry, client: ProtonClient
    ) -> None:
        minutes = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_MINUTES)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(minutes=minutes),
        )
        self.client = client
        self.all_calendars: dict[str, ProtonCalendar] = {}
        self.filters = [
            text.casefold() for f in entry.options.get(CONF_FILTERS, []) if (text := f.strip())
        ]

    @property
    def selected_ids(self) -> list[str]:
        return list(self.config_entry.options.get(CONF_CALENDARS, []))

    @property
    def lookahead(self) -> timedelta:
        return timedelta(
            days=self.config_entry.options.get(CONF_LOOKAHEAD_DAYS, DEFAULT_LOOKAHEAD_DAYS)
        )

    async def async_persist_session(self, session: Session) -> None:
        """Store rotated tokens so the session survives restarts."""
        self.hass.config_entries.async_update_entry(
            self.config_entry,
            data={**self.config_entry.data, CONF_SESSION: session.as_dict()},
        )

    async def _async_update_data(self) -> CalendarData:
        now = dt_util.now()
        start = dt_util.start_of_local_day(now) - timedelta(days=LOOKBEHIND_DAYS)
        end = start + self.lookahead + timedelta(days=LOOKBEHIND_DAYS + 1)
        try:
            calendars = await self.client.list_calendars()
            self.all_calendars = {c.id: c for c in calendars}
            data = CalendarData(window_start=start, window_end=end)
            for calendar_id in self.selected_ids:
                calendar = self.all_calendars.get(calendar_id)
                if calendar is None:
                    _LOGGER.warning("Selected calendar %s no longer exists", calendar_id)
                    continue
                data.calendars[calendar_id] = calendar
                data.events[calendar_id] = await self._async_fetch(calendar, start, end)
        except ProtonAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except ProtonError as err:
            raise UpdateFailed(f"Error communicating with Proton: {err}") from err
        return data

    async def _async_fetch(
        self, calendar: ProtonCalendar, start: datetime, end: datetime
    ) -> list[Occurrence]:
        tz = dt_util.get_default_time_zone()
        cards = await self.client.fetch_event_cards(
            calendar,
            int(start.timestamp()),
            int(end.timestamp()),
            str(self.hass.config.time_zone),
        )
        occurrences = await self.hass.async_add_executor_job(expand_events, cards, start, end, tz)
        return [o for o in occurrences if self._matches(o)]

    def _matches(self, occurrence: Occurrence) -> bool:
        """Text filters: keep events whose title or description contains any filter."""
        if not self.filters:
            return True
        text = f"{occurrence.summary}\n{occurrence.description or ''}".casefold()
        return any(f in text for f in self.filters)

    async def async_get_occurrences(
        self, calendar_id: str, start: datetime, end: datetime
    ) -> list[Occurrence]:
        """Occurrences in a window: from cache when possible, else fetched on demand."""
        data = self.data
        tz = dt_util.get_default_time_zone()
        if (
            data
            and calendar_id in data.events
            and data.window_start <= start
            and end <= data.window_end
        ):
            return [
                o
                for o in data.events[calendar_id]
                if (o.start_datetime(tz) < end and o.end_datetime(tz) > start)
                or (
                    o.start_datetime(tz) == o.end_datetime(tz)
                    and start <= o.start_datetime(tz) < end
                )
            ]
        calendar = (data.calendars.get(calendar_id) if data else None) or self.all_calendars.get(
            calendar_id
        )
        if calendar is None:
            return []
        try:
            return await self._async_fetch(calendar, start, end)
        except ProtonAuthError as err:
            self.config_entry.async_start_reauth(self.hass)
            raise UpdateFailed(str(err)) from err
        except ProtonError as err:
            _LOGGER.warning("Could not fetch events from Proton: %s", err)
            return []
