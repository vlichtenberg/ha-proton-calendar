"""Turn decrypted Proton event cards into concrete event occurrences.

Proton splits every event into several iCalendar "cards" (signed cleartext
with times/recurrence, encrypted with summary/description/location, and a
calendar-specific card with status). This module merges those cards back into
one VEVENT and expands recurrences into occurrences within a window.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, tzinfo
import logging
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil import rrule

_LOGGER = logging.getLogger(__name__)

MULTI_VALUE_PROPERTIES = {"EXDATE", "RDATE", "ATTENDEE", "CATEGORIES"}
MAX_OCCURRENCES = 5000

_DURATION_RE = re.compile(
    r"^(?P<sign>[+-])?P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)
_UNTIL_RE = re.compile(r"UNTIL=(\d{8})(T\d{6})?(Z)?")


@dataclass
class EventCards:
    """The decrypted iCalendar parts of one Proton event."""

    event_id: str
    calendar_id: str
    cards: list[str]


@dataclass(frozen=True)
class Property:
    """A single iCalendar content line."""

    params: dict[str, str]
    value: str


@dataclass
class Occurrence:
    """One concrete occurrence of an event."""

    uid: str
    summary: str
    start: date | datetime
    end: date | datetime
    description: str | None = None
    location: str | None = None
    recurrence_id: str | None = None
    rrule: str | None = None

    @property
    def all_day(self) -> bool:
        return not isinstance(self.start, datetime)

    def start_datetime(self, tz: tzinfo) -> datetime:
        return _as_datetime(self.start, tz)

    def end_datetime(self, tz: tzinfo) -> datetime:
        return _as_datetime(self.end, tz)


# --------------------------------------------------------------------- parsing


def _unfold(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        elif raw:
            lines.append(raw)
    return lines


def _split_line(line: str) -> tuple[str, dict[str, str], str]:
    in_quotes = False
    for index, char in enumerate(line):
        if char == '"':
            in_quotes = not in_quotes
        elif char == ":" and not in_quotes:
            head, value = line[:index], line[index + 1 :]
            break
    else:
        return line.upper(), {}, ""
    parts = re.findall(r'(?:[^;"]|"[^"]*")+', head)
    name = parts[0].upper()
    params: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        params[key.upper()] = val.strip('"')
    return name, params, value


def unescape_text(value: str) -> str:
    """Undo iCalendar TEXT escaping."""
    out = []
    chars = iter(value)
    for char in chars:
        if char == "\\":
            nxt = next(chars, "")
            out.append("\n" if nxt in ("n", "N") else nxt)
        else:
            out.append(char)
    return "".join(out)


def parse_vevent(card: str) -> dict[str, list[Property]]:
    """Return the properties of the first VEVENT in an iCalendar text."""
    props: dict[str, list[Property]] = defaultdict(list)
    depth = 0
    in_event = False
    for line in _unfold(card):
        name, params, value = _split_line(line)
        if name == "BEGIN":
            if value.upper() == "VEVENT" and not in_event:
                in_event = True
            elif in_event:
                depth += 1
            continue
        if name == "END":
            if in_event and depth:
                depth -= 1
            elif in_event and value.upper() == "VEVENT":
                break
            continue
        if in_event and not depth:
            props[name].append(Property(params, value))
    return dict(props)


def merge_cards(cards: list[str]) -> dict[str, list[Property]]:
    """Merge the VEVENTs of all cards; the first occurrence of a property wins."""
    merged: dict[str, list[Property]] = {}
    for card in cards:
        for name, values in parse_vevent(card).items():
            if name in MULTI_VALUE_PROPERTIES:
                merged.setdefault(name, []).extend(values)
            elif name not in merged:
                merged[name] = values
    return merged


# --------------------------------------------------------------------- values


def _zone(tzid: str | None, default: tzinfo) -> tzinfo:
    if not tzid:
        return default
    try:
        return ZoneInfo(tzid.strip("/"))
    except (ZoneInfoNotFoundError, ValueError):
        _LOGGER.debug("Unknown TZID %s, using default time zone", tzid)
        return default


def parse_datetime(prop: Property, default_tz: tzinfo) -> date | datetime:
    """Parse a DATE or DATE-TIME property value."""
    value = prop.value.strip().split(",")[0]
    if prop.params.get("VALUE", "").upper() == "DATE" or len(value) == 8:
        return datetime.strptime(value[:8], "%Y%m%d").date()
    naive = datetime.strptime(value.rstrip("Z")[:15], "%Y%m%dT%H%M%S")
    if value.endswith("Z"):
        return naive.replace(tzinfo=ZoneInfo("UTC"))
    return naive.replace(tzinfo=_zone(prop.params.get("TZID"), default_tz))


def parse_datetime_list(prop: Property, default_tz: tzinfo) -> list[date | datetime]:
    """Parse a comma-separated EXDATE/RDATE value."""
    return [
        parse_datetime(Property(prop.params, item), default_tz)
        for item in prop.value.split(",")
        if item.strip()
    ]


def parse_duration(value: str) -> timedelta:
    """Parse an iCalendar DURATION value."""
    match = _DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid duration {value}")
    parts = {k: int(v) for k, v in match.groupdict().items() if v and k != "sign"}
    delta = timedelta(
        weeks=parts.get("weeks", 0),
        days=parts.get("days", 0),
        hours=parts.get("hours", 0),
        minutes=parts.get("minutes", 0),
        seconds=parts.get("seconds", 0),
    )
    return -delta if match.group("sign") == "-" else delta


def _as_datetime(value: date | datetime, tz: tzinfo) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.combine(value, time(), tzinfo=tz)


def _key(value: date | datetime) -> object:
    """Normalize a recurrence identifier for comparisons."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.date() if value.time() == time() else value
        return value.timestamp()
    return value


def _sanitize_rrule(value: str, dtstart: datetime) -> str:
    """Make UNTIL compatible with dateutil's aware/naive rules."""

    def fix(match: re.Match[str]) -> str:
        day, clock, utc = match.group(1), match.group(2), match.group(3)
        if dtstart.tzinfo is None:
            return f"UNTIL={day}{clock or 'T235959'}"
        if utc:
            return match.group(0)
        local = datetime.strptime(day + (clock or "T235959"), "%Y%m%dT%H%M%S").replace(
            tzinfo=dtstart.tzinfo
        )
        return "UNTIL=" + local.astimezone(ZoneInfo("UTC")).strftime("%Y%m%dT%H%M%SZ")

    return _UNTIL_RE.sub(fix, value)


# ----------------------------------------------------------------- expansion


@dataclass
class _Event:
    uid: str
    props: dict[str, list[Property]]
    start: date | datetime
    duration: timedelta
    recurrence_id: date | datetime | None

    def text(self, name: str) -> str | None:
        values = self.props.get(name)
        return unescape_text(values[0].value) if values else None

    @property
    def cancelled(self) -> bool:
        return (self.text("STATUS") or "").upper() == "CANCELLED"

    def occurrence(self, start: date | datetime, recurrence_id: str | None) -> Occurrence:
        return Occurrence(
            uid=self.uid,
            summary=self.text("SUMMARY") or "(no title)",
            description=self.text("DESCRIPTION") or None,
            location=self.text("LOCATION") or None,
            start=start,
            end=start + self.duration,
            recurrence_id=recurrence_id,
            rrule=self.props["RRULE"][0].value if "RRULE" in self.props else None,
        )


def _build_event(props: dict[str, list[Property]], default_tz: tzinfo) -> _Event | None:
    if "DTSTART" not in props:
        return None
    start = parse_datetime(props["DTSTART"][0], default_tz)
    if "DTEND" in props:
        end = parse_datetime(props["DTEND"][0], default_tz)
        if isinstance(start, datetime) and not isinstance(end, datetime):
            end = _as_datetime(end, start.tzinfo or default_tz)
        elif not isinstance(start, datetime) and isinstance(end, datetime):
            end = end.date()
        duration = end - start
    elif "DURATION" in props:
        duration = parse_duration(props["DURATION"][0].value)
    else:
        duration = timedelta(days=1) if not isinstance(start, datetime) else timedelta()
    duration = max(duration, timedelta())
    if not isinstance(start, datetime) and duration < timedelta(days=1):
        duration = timedelta(days=1)
    recurrence_id = (
        parse_datetime(props["RECURRENCE-ID"][0], default_tz) if "RECURRENCE-ID" in props else None
    )
    uid = props["UID"][0].value if "UID" in props else ""
    return _Event(uid, props, start, duration, recurrence_id)


def _overlaps(
    start: date | datetime,
    end: date | datetime,
    window_start: datetime,
    window_end: datetime,
    tz: tzinfo,
) -> bool:
    s, e = _as_datetime(start, tz), _as_datetime(end, tz)
    if e == s:
        return window_start <= s < window_end
    return s < window_end and e > window_start


def _expand_master(
    master: _Event,
    window_start: datetime,
    window_end: datetime,
    tz: tzinfo,
    overridden: set[object],
) -> list[Occurrence]:
    all_day = not isinstance(master.start, datetime)
    dtstart = (
        datetime.combine(master.start, time()) if all_day else master.start  # type: ignore[arg-type]
    )
    ruleset = rrule.rruleset()
    for prop in master.props.get("RRULE", []):
        ruleset.rrule(
            rrule.rrulestr(_sanitize_rrule(prop.value, dtstart), dtstart=dtstart)  # type: ignore[arg-type]
        )
    ruleset.rdate(dtstart)  # DTSTART is always the first instance

    def normalize(value: date | datetime) -> datetime:
        if all_day:
            return datetime.combine(value.date() if isinstance(value, datetime) else value, time())
        return _as_datetime(value, tz)

    for prop in master.props.get("RDATE", []):
        for value in parse_datetime_list(prop, tz):
            ruleset.rdate(normalize(value))
    for prop in master.props.get("EXDATE", []):
        for value in parse_datetime_list(prop, tz):
            ruleset.exdate(normalize(value))

    if all_day:
        lower = datetime.combine(window_start.astimezone(tz).date(), time()) - master.duration
        upper = datetime.combine(window_end.astimezone(tz).date(), time()) + timedelta(days=1)
    else:
        lower = window_start - master.duration
        upper = window_end

    occurrences: list[Occurrence] = []
    for instance in ruleset.between(lower, upper, inc=True):
        start: date | datetime = instance.date() if all_day else instance
        if _key(start) in overridden:
            continue
        end = start + master.duration
        if not _overlaps(start, end, window_start, window_end, tz):
            continue
        rid = start.isoformat() if master.props.get("RRULE") else None
        occurrences.append(master.occurrence(start, rid))
        if len(occurrences) >= MAX_OCCURRENCES:
            break
    return occurrences


def expand_events(
    events: list[EventCards],
    window_start: datetime,
    window_end: datetime,
    default_tz: tzinfo,
) -> list[Occurrence]:
    """Expand decrypted events into occurrences overlapping the window."""
    by_uid: dict[str, list[_Event]] = defaultdict(list)
    for item in events:
        try:
            parsed = _build_event(merge_cards(item.cards), default_tz)
        except (ValueError, KeyError) as err:
            _LOGGER.warning("Skipping unparsable event %s: %s", item.event_id, err)
            continue
        if parsed is not None:
            by_uid[parsed.uid or item.event_id].append(parsed)

    occurrences: list[Occurrence] = []
    for group in by_uid.values():
        masters = [e for e in group if e.recurrence_id is None]
        overrides = [e for e in group if e.recurrence_id is not None]
        overridden = {_key(e.recurrence_id) for e in overrides if e.recurrence_id}

        for master in masters:
            if master.cancelled:
                continue
            if "RRULE" in master.props or "RDATE" in master.props:
                try:
                    occurrences.extend(
                        _expand_master(master, window_start, window_end, default_tz, overridden)
                    )
                except (ValueError, TypeError) as err:
                    _LOGGER.warning("Cannot expand recurrence of %s: %s", master.uid, err)
            elif _overlaps(
                master.start,
                master.start + master.duration,
                window_start,
                window_end,
                default_tz,
            ):
                occurrences.append(master.occurrence(master.start, None))

        for override in overrides:
            if override.cancelled:
                continue
            if _overlaps(
                override.start,
                override.start + override.duration,
                window_start,
                window_end,
                default_tz,
            ):
                assert override.recurrence_id is not None
                occurrences.append(
                    override.occurrence(override.start, override.recurrence_id.isoformat())
                )

    occurrences.sort(key=lambda o: (o.start_datetime(default_tz), o.summary))
    return occurrences
