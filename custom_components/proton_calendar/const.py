"""Constants for the Proton Calendar integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "proton_calendar"

CONF_SESSION: Final = "session"
CONF_CALENDARS: Final = "calendars"
CONF_LOOKAHEAD_DAYS: Final = "lookahead_days"
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_TOTP: Final = "totp"
CONF_MAILBOX_PASSWORD: Final = "mailbox_password"
CONF_FILTERS: Final = "filters"
CONF_SHOW_SIDEBAR_PANEL: Final = "show_sidebar_panel"

DEFAULT_LOOKAHEAD_DAYS: Final = 30
DEFAULT_SHOW_SIDEBAR_PANEL: Final = True
DEFAULT_SCAN_INTERVAL_MINUTES: Final = 15
MIN_SCAN_INTERVAL_MINUTES: Final = 5

# Days of history kept in the cache so events that started yesterday still show.
LOOKBEHIND_DAYS: Final = 1
