# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-20

### Added
- Proton sign-in from the UI: SRP login with verified modulus, CAPTCHA (human verification),
  TOTP two-factor authentication and two-password (mailbox password) accounts.
- Local credential store: session tokens and the derived key passphrase are kept in the config
  entry; the password is never stored. Tokens are refreshed and persisted automatically.
- Calendar selection during setup and in the options, plus cache window and refresh interval.
- Text filters on event title and description, and an option to show or hide the Calendar
  sidebar panel.
- One `calendar` entity per selected calendar, usable for schedules, calendar triggers and
  `calendar.get_events`; on-demand fetching outside the cached window.
- Local decryption of events with a built-in read-only OpenPGP implementation, and recurrence
  expansion with exceptions, EXDATEs, all-day events and time zones.
- Re-authentication flow, session revocation on removal, and redacted diagnostics.
