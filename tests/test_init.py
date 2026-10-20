"""Tests for setting up Proton Calendar and its calendar entities."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from freezegun.api import FrozenDateTimeFactory
from homeassistant.components.frontend import async_panel_exists
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_USERNAME, STATE_OFF, STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed

from custom_components.proton_calendar.const import (
    CONF_CALENDARS,
    CONF_FILTERS,
    CONF_SESSION,
    CONF_SHOW_SIDEBAR_PANEL,
    DOMAIN,
)
from custom_components.proton_calendar.proton import (
    EventCards,
    ProtonAuthError,
    ProtonCalendar,
    ProtonConnectionError,
    Session,
)

CALENDARS = [
    ProtonCalendar("cal-1", "Personal", "#f00", "", 0, 1, "m1", "a1", "me@example.com"),
    ProtonCalendar("cal-2", "Work", "#0f0", "", 0, 1, "m2", "a1", "me@example.com"),
]


def _card(*lines: str) -> str:
    return "\r\n".join(["BEGIN:VCALENDAR", "BEGIN:VEVENT", *lines, "END:VEVENT", "END:VCALENDAR"])


@pytest.fixture
def entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id="user-1",
        title="me@example.com",
        data={
            CONF_USERNAME: "me@example.com",
            CONF_SESSION: Session("uid", "a", "r", "k", "user-1").as_dict(),
        },
        options={CONF_CALENDARS: ["cal-1"]},
    )
    entry.add_to_hass(hass)
    return entry


@pytest.fixture
def client() -> MagicMock:
    client = MagicMock()
    client.app_version = "web-calendar@test"
    client.list_calendars = AsyncMock(return_value=CALENDARS)

    async def fetch(calendar, start, end, tz):
        return [
            EventCards(
                "e1",
                calendar.id,
                [
                    _card("UID:e1", "DTSTART:20261020T090000Z", "DTEND:20261020T100000Z"),
                    _card("SUMMARY:Boiler on", "DESCRIPTION:heat"),
                ],
            ),
            EventCards(
                "e2",
                calendar.id,
                [
                    _card(
                        "UID:e2",
                        "DTSTART:20261020T120000Z",
                        "DTEND:20261020T130000Z",
                        "RRULE:FREQ=WEEKLY",
                        "SUMMARY:Lunch",
                    )
                ],
            ),
        ]

    client.fetch_event_cards = AsyncMock(side_effect=fetch)
    client.logout = AsyncMock()
    return client


async def _setup(hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock) -> None:
    with patch("custom_components.proton_calendar.create_client", return_value=client):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()


async def test_setup_creates_selected_calendars(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    await hass.config.async_set_time_zone("UTC")
    freezer.move_to("2026-10-20T08:00:00+00:00")
    await _setup(hass, entry, client)
    assert entry.state is ConfigEntryState.LOADED

    state = hass.states.get("calendar.proton_calendar_me_example_com_personal")
    assert state is not None
    assert hass.states.get("calendar.proton_calendar_me_example_com_work") is None
    assert state.state == STATE_OFF
    assert state.attributes["message"] == "Boiler on"
    assert state.attributes["color"] == "#f00"

    freezer.move_to("2026-10-20T09:30:00+00:00")
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert hass.states.get("calendar.proton_calendar_me_example_com_personal").state == STATE_ON


async def test_get_events_service_expands_recurrence(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to("2026-10-20T08:00:00+00:00")
    await _setup(hass, entry, client)
    start = dt_util.parse_datetime("2026-10-19T00:00:00+00:00")
    response = await hass.services.async_call(
        "calendar",
        "get_events",
        {"start_date_time": start, "end_date_time": start + timedelta(days=14)},
        target={"entity_id": "calendar.proton_calendar_me_example_com_personal"},
        blocking=True,
        return_response=True,
    )
    events = response["calendar.proton_calendar_me_example_com_personal"]["events"]
    assert [e["summary"] for e in events] == ["Boiler on", "Lunch", "Lunch"]


async def test_on_demand_fetch_outside_cache(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to("2026-10-20T08:00:00+00:00")
    await _setup(hass, entry, client)
    calls = client.fetch_event_cards.await_count
    coordinator = entry.runtime_data
    start = dt_util.parse_datetime("2027-03-01T00:00:00+00:00")
    occurrences = await coordinator.async_get_occurrences("cal-1", start, start + timedelta(days=7))
    assert client.fetch_event_cards.await_count == calls + 1
    assert [o.summary for o in occurrences] == ["Lunch"]


async def test_auth_failure_starts_reauth(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    client.list_calendars.side_effect = ProtonAuthError("expired")
    with patch("custom_components.proton_calendar.create_client", return_value=client):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


async def test_connection_failure_retries(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    client.list_calendars.side_effect = ProtonConnectionError("down")
    with patch("custom_components.proton_calendar.create_client", return_value=client):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_options_flow_updates_selection(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    await _setup(hass, entry, client)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["step_id"] == "init"
    with patch("custom_components.proton_calendar.create_client", return_value=client):
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                CONF_CALENDARS: ["cal-1", "cal-2"],
                "lookahead_days": 14,
                "scan_interval": 30,
                CONF_SHOW_SIDEBAR_PANEL: True,
            },
        )
        await hass.async_block_till_done()
    assert entry.options[CONF_CALENDARS] == ["cal-1", "cal-2"]
    assert hass.states.get("calendar.proton_calendar_me_example_com_work") is not None


async def test_unload_and_remove_revokes_session(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    await _setup(hass, entry, client)
    with patch("custom_components.proton_calendar.create_client", return_value=client):
        await hass.config_entries.async_remove(entry.entry_id)
        await hass.async_block_till_done()
    client.logout.assert_awaited_once()


async def test_diagnostics_redacts_secrets(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    from custom_components.proton_calendar.diagnostics import (
        async_get_config_entry_diagnostics,
    )

    await _setup(hass, entry, client)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["entry"]["data"][CONF_SESSION] == "**REDACTED**"
    assert "Boiler" not in str(diag)


async def test_text_filters_limit_events(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to("2026-10-20T08:00:00+00:00")
    hass.config_entries.async_update_entry(entry, options={**entry.options, CONF_FILTERS: ["HEAT"]})
    await _setup(hass, entry, client)
    events = entry.runtime_data.data.events["cal-1"]
    # "heat" matches the description of "Boiler on"; "Lunch" is filtered out.
    assert [o.summary for o in events] == ["Boiler on"]


async def test_sidebar_panel_option(
    hass: HomeAssistant, entry: MockConfigEntry, client: MagicMock
) -> None:
    await _setup(hass, entry, client)
    assert async_panel_exists(hass, "calendar")

    with patch("custom_components.proton_calendar.create_client", return_value=client):
        hass.config_entries.async_update_entry(
            entry, options={**entry.options, CONF_SHOW_SIDEBAR_PANEL: False}
        )
        await hass.async_block_till_done()
    assert not async_panel_exists(hass, "calendar")

    await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert async_panel_exists(hass, "calendar")
