# Proton Calendar for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/v/release/vlichtenberg/ha-proton-calendar)](https://github.com/vlichtenberg/ha-proton-calendar/releases)
[![Validate](https://github.com/vlichtenberg/ha-proton-calendar/actions/workflows/validate.yml/badge.svg)](https://github.com/vlichtenberg/ha-proton-calendar/actions/workflows/validate.yml)
[![Tests](https://github.com/vlichtenberg/ha-proton-calendar/actions/workflows/tests.yml/badge.svg)](https://github.com/vlichtenberg/ha-proton-calendar/actions/workflows/tests.yml)

Bring your **end-to-end encrypted [Proton Calendar](https://proton.me/calendar)** into Home Assistant.
Sign in once (with two-factor authentication), pick the calendars you want, and every one becomes a
`calendar` entity. Use it on your dashboards, as a schedule, and in triggers and automations.

[![Open your Home Assistant instance and open this repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=vlichtenberg&repository=ha-proton-calendar&category=integration)
[![Open your Home Assistant instance and start setting up Proton Calendar.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=proton_calendar)

> [!NOTE]
> This is a community project. It is not made, endorsed or supported by Proton AG.
> It uses the same (undocumented) API as the Proton web apps, which Proton can change at any time.

## Features

- **Sign in from the Home Assistant UI**, including CAPTCHA (human verification), TOTP two-factor
  authentication and accounts with a separate mailbox password.
- **Local credential store**: your password is used once to sign in and derive the key that unlocks
  your encryption keys. Only the Proton session and that derived key are stored on your Home Assistant
  machine. Your password is never saved.
- **Decrypted on your own machine**: events are decrypted locally with your keys. Nothing goes through a
  third-party server.
- **Choose your calendars**: personal, shared and subscribed calendars. You can change the selection
  later.
- **Recurring events** with exceptions, deleted occurrences, all-day events and time zones (including
  daylight-saving changes).
- **Works with everything that understands calendars**: the calendar dashboard, the `calendar.get_events`
  action, calendar triggers (`start`/`end` with an offset), and state conditions.
- **Automatic session upkeep**: tokens are refreshed and stored automatically. If Proton ends the
  session, Home Assistant asks you to sign in again (re-authentication).

## Requirements

- Home Assistant **2025.2** or newer.
- A Proton account with Proton Calendar (free plans work).
- For two-factor authentication: an **authenticator app (TOTP)**. Accounts that *only* have a security
  key (FIDO2/WebAuthn) as second factor cannot sign in, because security keys need a browser. You can
  add an authenticator app next to your security key in Proton's security settings.

### Dependencies

You don't need to install anything else. In particular, you **don't** need Proton Bridge, a Proton CLI,
or Proton's Go libraries (`go-proton-api`, `gopenpgp`).

Proton Bridge doesn't serve calendars, and Proton has no official calendar CLI. Shipping Go binaries
inside a Home Assistant integration would also break on many installations, because of the different
CPU architectures and Home Assistant OS. So this integration has its own small pure-Python
implementation of the parts it needs:

| Part | Implementation |
| --- | --- |
| Login (Proton's SRP-6a variant, password hashing) | Ported from Proton's MIT-licensed [`go-srp`](https://github.com/ProtonMail/go-srp) and checked against Proton's own test vectors |
| SRP modulus verification | Checks the signature against Proton's published signing key |
| OpenPGP decryption (keys, session keys, messages) | Read-only, built on `cryptography` |
| Recurrence expansion | `python-dateutil` |

`bcrypt`, `cryptography` and `aiohttp` already ship with Home Assistant. `python-dateutil` is installed
automatically when it's missing.

## Installation

### HACS (recommended)

1. Select the **Open in HACS** button above. Or, in HACS, open the ⋮ menu → *Custom repositories* and
   add `https://github.com/vlichtenberg/ha-proton-calendar` with type **Integration**.
2. Select **Download** and restart Home Assistant.
3. Select the **Add integration** button above, or go to **Settings → Devices & services → Add
   integration** and search for **Proton Calendar**.

### Manual

1. Copy `custom_components/proton_calendar` from the [latest release](https://github.com/vlichtenberg/ha-proton-calendar/releases)
   into the `custom_components` folder of your Home Assistant configuration.
2. Restart Home Assistant and add the integration as described above.

## Configuration

The setup dialog walks you through these steps:

1. **Sign in**: your Proton email address (or username) and password.
2. **Human verification** *(only if Proton asks for it)*: open the link shown, solve the CAPTCHA, wait
   until the page confirms, then come back and select *Submit*.
3. **Two-factor authentication** *(if enabled)*: the 6-digit code from your authenticator app.
4. **Mailbox password** *(only for accounts in two-password mode)*.
5. **Choose calendars**: tick the calendars to add.

Each selected calendar becomes an entity such as `calendar.proton_calendar_you_proton_me_personal`.
The calendars belong to the **Proton Calendar (*your account*)** device. If you installed through HACS,
you also see a **Proton Calendar** device from HACS: it holds the update entity for this
integration. Home Assistant lets a device belong to only one integration, so these stay separate.

### Options

Go to **Settings → Devices & services → Proton Calendar → Configure** to change:

| Option | Default | Description |
| --- | --- | --- |
| Calendars | chosen during setup | Which calendars become entities |
| Days to cache ahead | 30 | Events in this window are kept in memory for instant state updates and triggers. The calendar dashboard can still browse further; those events are fetched on demand. |
| Refresh interval | 15 min | How often Proton is checked for new or changed events (minimum 5 minutes) |
| Text filters | none | Only events whose title or description contains one of these texts (case-insensitive) reach Home Assistant. Empty means all events of the selected calendars. |
| Show Calendar in the sidebar | on | Shows or hides Home Assistant's Calendar panel for **all users**. See [Hiding Calendar in the sidebar](#hiding-calendar-in-the-sidebar). |

### Hiding Calendar in the sidebar

The **Calendar** item in the sidebar is not part of this integration. It is Home Assistant's own
calendar panel, which appears as soon as any calendar exists, and it shows the calendars of every
integration. There are two ways to hide it:

- **Just for yourself (native Home Assistant)**: go to your **Profile** (your name at the bottom of
  the sidebar) → **General** → **Change the order and hide items from the sidebar** → select
  **Edit**, hide *Calendar* and save. You can also long-press the *Home Assistant* title at the top
  of the sidebar to start editing. This is per user and doesn't affect anyone else.
- **For everyone**: turn off **Show Calendar in the sidebar** in this integration's options. This
  removes the panel for all users and all calendars. Turn the option back on, or remove the
  integration, to bring it back.

Hiding the panel doesn't change your calendar entities: their states, triggers and the
`calendar.get_events` action keep working.

## Using your calendars

A calendar entity is **on** while an event is happening and **off** otherwise. Its attributes describe
the current or next event (`message`, `start_time`, `end_time`, `location`, `description`, `all_day`).

### As a schedule

Because the state follows your events, a Proton calendar works like a Home Assistant schedule that you
edit from the Proton apps. For example, keep a calendar called *Heating* with the time blocks you want
the heating on:

```yaml
automation:
  - alias: "Heating follows Proton schedule"
    triggers:
      - trigger: state
        entity_id: calendar.proton_calendar_you_proton_me_heating
    actions:
      - action: climate.set_preset_mode
        target:
          entity_id: climate.living_room
        data:
          preset_mode: "{{ 'comfort' if trigger.to_state.state == 'on' else 'eco' }}"
```

You can also use it as a condition anywhere:

```yaml
conditions:
  - condition: state
    entity_id: calendar.proton_calendar_you_proton_me_work
    state: "off" # not in a meeting
```

### Calendar triggers

Run an automation at the start or end of matching events, optionally with an offset:

```yaml
automation:
  - alias: "Warm up the car before early appointments"
    triggers:
      - trigger: calendar
        event: start
        offset: "-0:30:0"
        entity_id: calendar.proton_calendar_you_proton_me_personal
    conditions:
      - condition: template
        value_template: "{{ 'dentist' in trigger.calendar_event.summary | lower }}"
    actions:
      - action: switch.turn_on
        target:
          entity_id: switch.car_heater
```

### Only events with a keyword

Create a template binary sensor that is on only during events whose title contains a word:

```yaml
template:
  - binary_sensor:
      - name: "Guests over"
        state: >
          {{ is_state('calendar.proton_calendar_you_proton_me_family', 'on')
             and 'guests' in state_attr('calendar.proton_calendar_you_proton_me_family', 'message') | lower }}
```

> [!TIP]
> When several events overlap, the entity state and attributes show only one of them. If you need all
> of them, use the `calendar.get_events` action or calendar triggers, which see every event.

### Listing events

```yaml
action: calendar.get_events
target:
  entity_id: calendar.proton_calendar_you_proton_me_personal
data:
  duration:
    days: 7
response_variable: agenda
```

## Security and privacy

- **What is stored**: the Proton session (UID, access and refresh token) and the *derived key
  passphrase*. Proton's clients derive this passphrase from your password with bcrypt and a per-key salt.
  It is stored in Home Assistant's config entry storage (`.storage/core.config_entries`), like every other
  integration's credentials. Protect your Home Assistant backups accordingly.
- **What is not stored**: your password, your 2FA secret, or any decrypted event data on disk. Decrypted
  events are only kept in memory.
- **Revoking access**: removing the integration ends the session at Proton. You can also end it under
  *Proton → Settings → Security → Session management*; Home Assistant will then ask you to sign in
  again.
- **Read-only**: the integration never creates, changes or deletes events.
- **Diagnostics** downloads leave out tokens, keys, email addresses and event contents.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| *Incorrect username or password* | Try signing in at [account.proton.me](https://account.proton.me). For accounts with a separate mailbox password, enter the **login** password here; you're asked for the mailbox password afterwards. |
| The human verification step keeps coming back | Each attempt uses a new link. Open the **current** link, solve the CAPTCHA, wait until the page confirms, then submit. If it keeps happening, wait a while; Proton asks for verification more often after many attempts. |
| *Only has a security key as second factor* | Add an authenticator app (TOTP) as an extra second factor in Proton's security settings. |
| An event is missing | Check the log for `Skipping event ... could not be decrypted`. Newer key types, like post-quantum or v6 keys, aren't supported yet. Please [open an issue](https://github.com/vlichtenberg/ha-proton-calendar/issues). |
| *Re-authentication required* | The session ended (revoked, password changed, or expired). Select **Reconfigure** and sign in again. |

To see what is happening, enable debug logging:

```yaml
logger:
  logs:
    custom_components.proton_calendar: debug
```

## Limitations

- Read-only: events cannot be created or edited from Home Assistant.
- Security-key-only (FIDO2) two-factor accounts cannot sign in.
- Only OpenPGP v4 keys (Curve25519 and RSA) are supported. These are what Proton accounts use today.
- Proton may change its private API. If it does, the integration may stop working until it is updated.
  The client adapts to Proton's minimum-app-version checks on its own.

## Development

```bash
pip install -r requirements_test.txt
pytest
```

The tests don't need a Proton account. The OpenPGP code is tested against keys and messages made with
GnuPG, and the SRP code against Proton's own test vectors.

## License

[MIT](LICENSE). The SRP code is ported from Proton's MIT-licensed `go-srp`; see [NOTICE](NOTICE).
