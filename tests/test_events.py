"""Tests for merging Proton event cards and expanding recurrences."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from custom_components.proton_calendar.proton.events import (
    EventCards,
    expand_events,
    merge_cards,
    parse_duration,
    unescape_text,
)

AMS = ZoneInfo("Europe/Amsterdam")


def _card(*lines: str) -> str:
    return "\r\n".join(
        ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", *lines, "END:VEVENT", "END:VCALENDAR"]
    )


def _event(event_id: str, *cards: str) -> EventCards:
    return EventCards(event_id=event_id, calendar_id="cal", cards=list(cards))


def _window(start: datetime, days: int) -> tuple[datetime, datetime]:
    return start, start + timedelta(days=days)


def test_merge_cards_combines_signed_and_encrypted_parts() -> None:
    signed = _card(
        "UID:abc",
        "DTSTART;TZID=Europe/Amsterdam:20261020T090000",
        "DTEND;TZID=Europe/Amsterdam:20261020T100000",
    )
    encrypted = _card(
        "SUMMARY:Dentist", "DESCRIPTION:Bring card\\, ID\\nand smile", "LOCATION:Main st"
    )
    merged = merge_cards([signed, encrypted])
    assert merged["UID"][0].value == "abc"
    assert merged["SUMMARY"][0].value == "Dentist"
    assert unescape_text(merged["DESCRIPTION"][0].value) == "Bring card, ID\nand smile"


def test_folded_lines_and_nested_alarm() -> None:
    card = _card(
        "UID:fold",
        "SUMMARY:A very long",
        "  title",
        "DTSTART:20261020T080000Z",
        "BEGIN:VALARM",
        "SUMMARY:alarm summary must be ignored",
        "END:VALARM",
    )
    merged = merge_cards([card])
    assert merged["SUMMARY"][0].value == "A very long title"


def test_single_timed_event() -> None:
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 7)
    events = [
        _event(
            "1",
            _card(
                "UID:1",
                "DTSTART;TZID=Europe/Amsterdam:20261020T090000",
                "DTEND;TZID=Europe/Amsterdam:20261020T103000",
            ),
            _card("SUMMARY:Standup", "LOCATION:Office"),
        )
    ]
    [occ] = expand_events(events, start, end, AMS)
    assert occ.summary == "Standup"
    assert occ.location == "Office"
    assert occ.start == datetime(2026, 10, 20, 9, 0, tzinfo=AMS)
    assert occ.end - occ.start == timedelta(minutes=90)
    assert not occ.all_day


def test_all_day_event_with_duration() -> None:
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 7)
    events = [
        _event("1", _card("UID:2", "DTSTART;VALUE=DATE:20261021", "DURATION:P2D", "SUMMARY:Trip"))
    ]
    [occ] = expand_events(events, start, end, AMS)
    assert occ.all_day
    assert occ.start == date(2026, 10, 21)
    assert occ.end == date(2026, 10, 23)


def test_event_outside_window_is_dropped() -> None:
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 1)
    events = [_event("1", _card("UID:3", "DTSTART:20261101T080000Z", "DTEND:20261101T090000Z"))]
    assert expand_events(events, start, end, AMS) == []


def test_weekly_recurrence_with_exdate_and_override() -> None:
    master = _event(
        "m",
        _card(
            "UID:weekly",
            "DTSTART;TZID=Europe/Amsterdam:20261005T190000",
            "DTEND;TZID=Europe/Amsterdam:20261005T200000",
            "RRULE:FREQ=WEEKLY;BYDAY=MO",
            "EXDATE;TZID=Europe/Amsterdam:20261012T190000",
        ),
        _card("SUMMARY:Football"),
    )
    override = _event(
        "o",
        _card(
            "UID:weekly",
            "RECURRENCE-ID;TZID=Europe/Amsterdam:20261019T190000",
            "DTSTART;TZID=Europe/Amsterdam:20261019T200000",
            "DTEND;TZID=Europe/Amsterdam:20261019T210000",
        ),
        _card("SUMMARY:Football (late)"),
    )
    start, end = _window(datetime(2026, 10, 1, tzinfo=AMS), 30)
    occs = expand_events([master, override], start, end, AMS)
    assert [(o.start.day, o.start.hour, o.summary) for o in occs] == [
        (5, 19, "Football"),
        (19, 20, "Football (late)"),
        (26, 19, "Football"),
    ]
    assert occs[0].recurrence_id is not None
    assert occs[0].rrule == "FREQ=WEEKLY;BYDAY=MO"


def test_recurrence_keeps_wall_clock_across_dst() -> None:
    master = _event(
        "m",
        _card(
            "UID:dst",
            "DTSTART;TZID=Europe/Amsterdam:20261023T080000",
            "DTEND;TZID=Europe/Amsterdam:20261023T090000",
            "RRULE:FREQ=WEEKLY;COUNT=3",
            "SUMMARY:Gym",
        ),
    )
    start, end = _window(datetime(2026, 10, 20, tzinfo=AMS), 30)
    occs = expand_events([master], start, end, AMS)
    assert [o.start.hour for o in occs] == [8, 8, 8]
    # DST ends on 25 Oct 2026, so the UTC offset changes between occurrences.
    assert occs[0].start.utcoffset() != occs[1].start.utcoffset()


def test_recurrence_started_before_window() -> None:
    master = _event(
        "m",
        _card("UID:daily", "DTSTART;VALUE=DATE:20250101", "RRULE:FREQ=DAILY", "SUMMARY:Daily"),
    )
    start, end = _window(datetime(2026, 10, 20, tzinfo=AMS), 3)
    occs = expand_events([master], start, end, AMS)
    assert [o.start for o in occs] == [date(2026, 10, 20), date(2026, 10, 21), date(2026, 10, 22)]


def test_until_date_with_timed_start() -> None:
    master = _event(
        "m",
        _card(
            "UID:until",
            "DTSTART;TZID=Europe/Amsterdam:20261019T090000",
            "DTEND;TZID=Europe/Amsterdam:20261019T091500",
            "RRULE:FREQ=DAILY;UNTIL=20261021",
        ),
    )
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 10)
    assert len(expand_events([master], start, end, AMS)) == 3


def test_until_utc_with_all_day_start() -> None:
    master = _event(
        "m",
        _card(
            "UID:until2", "DTSTART;VALUE=DATE:20261019", "RRULE:FREQ=DAILY;UNTIL=20261020T215959Z"
        ),
    )
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 10)
    assert len(expand_events([master], start, end, AMS)) == 2


def test_cancelled_events_are_skipped() -> None:
    events = [
        _event(
            "1",
            _card("UID:x", "DTSTART:20261020T080000Z", "DTEND:20261020T090000Z"),
            _card("STATUS:CANCELLED"),
        ),
    ]
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 7)
    assert expand_events(events, start, end, AMS) == []


def test_unparsable_event_does_not_break_others() -> None:
    events = [
        _event("bad", _card("UID:bad", "DTSTART:garbage")),
        _event("good", _card("UID:good", "DTSTART:20261020T080000Z", "SUMMARY:ok")),
    ]
    start, end = _window(datetime(2026, 10, 19, tzinfo=AMS), 7)
    assert [o.summary for o in expand_events(events, start, end, AMS)] == ["ok"]


def test_parse_duration() -> None:
    assert parse_duration("PT1H30M") == timedelta(hours=1, minutes=30)
    assert parse_duration("P1W") == timedelta(weeks=1)
    assert parse_duration("-P1D") == timedelta(days=-1)
