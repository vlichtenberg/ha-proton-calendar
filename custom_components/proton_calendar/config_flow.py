"""Config flow for Proton Calendar: login with 2FA, then pick calendars."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntryState,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
import voluptuous as vol

from . import create_client
from .const import (
    CONF_CALENDARS,
    CONF_FILTERS,
    CONF_LOOKAHEAD_DAYS,
    CONF_MAILBOX_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SESSION,
    CONF_SHOW_SIDEBAR_PANEL,
    CONF_TOTP,
    DEFAULT_LOOKAHEAD_DAYS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_SHOW_SIDEBAR_PANEL,
    DOMAIN,
    MIN_SCAN_INTERVAL_MINUTES,
)
from .coordinator import ProtonCalendarConfigEntry
from .proton import (
    HumanVerificationFailed,
    HumanVerificationRequired,
    InvalidCredentials,
    InvalidMailboxPassword,
    InvalidTwoFactorCode,
    LoginResult,
    ProtonCalendar,
    ProtonClient,
    ProtonConnectionError,
    ProtonError,
    Session,
    UnsupportedTwoFactor,
)

_LOGGER = logging.getLogger(__name__)

PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def _calendar_selector(calendars: list[ProtonCalendar]) -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=[SelectOptionDict(value=c.id, label=c.name) for c in calendars],
            multiple=True,
        )
    )


class ProtonCalendarConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the login and calendar selection."""

    VERSION = 1

    def __init__(self) -> None:
        self._client: ProtonClient | None = None
        self._username: str = ""
        self._password: str = ""
        self._login: LoginResult | None = None
        self._hv: HumanVerificationRequired | None = None
        self._hv_failed = False
        self._calendars: list[ProtonCalendar] = []

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ProtonCalendarConfigEntry) -> OptionsFlow:
        return ProtonCalendarOptionsFlow()

    # ------------------------------------------------------------- password

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Ask for the Proton username and password."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._username = user_input[CONF_USERNAME].strip()
            self._password = user_input[CONF_PASSWORD]
            result = await self._async_login(errors)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_USERNAME): TextSelector(
                            TextSelectorConfig(type=TextSelectorType.EMAIL, autocomplete="username")
                        ),
                        vol.Required(CONF_PASSWORD): PASSWORD_SELECTOR,
                    }
                ),
                {CONF_USERNAME: self._username},
            ),
            errors=errors,
        )

    async def _async_login(
        self, errors: dict[str, str], hv_token: str | None = None
    ) -> ConfigFlowResult | None:
        self._client = create_client(self.hass)
        try:
            self._login = await self._client.login(self._username, self._password, hv_token)
        except HumanVerificationRequired as err:
            self._hv = err
            return await self.async_step_human_verification()
        except HumanVerificationFailed:
            # The challenge token is spent; sign in again to get a fresh CAPTCHA.
            self._hv_failed = True
            return await self._async_login(errors)
        except InvalidCredentials:
            errors["base"] = "invalid_auth"
        except UnsupportedTwoFactor:
            errors["base"] = "fido2_only"
        except ProtonConnectionError:
            errors["base"] = "cannot_connect"
        except ProtonError:
            _LOGGER.exception("Unexpected error during Proton login")
            errors["base"] = "unknown"
        else:
            if self._login.two_factor_required:
                return await self.async_step_totp()
            return await self._async_after_second_factor()
        return None

    async def async_step_human_verification(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Proton asks for a CAPTCHA; let the user solve it in the browser."""
        assert self._hv is not None
        errors: dict[str, str] = {}
        if self._hv_failed:
            self._hv_failed = False
            errors["base"] = "hv_failed"
        elif user_input is not None:
            result = await self._async_login(errors, hv_token=self._hv.token)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="human_verification",
            data_schema=vol.Schema({}),
            description_placeholders={"url": self._hv.url},
            errors=errors,
        )

    # ----------------------------------------------------------- second factor

    async def async_step_totp(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Ask for the authenticator app code."""
        assert self._client is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self._client.submit_totp(user_input[CONF_TOTP])
            except InvalidTwoFactorCode:
                errors["base"] = "invalid_2fa"
            except ProtonConnectionError:
                errors["base"] = "cannot_connect"
            except ProtonError:
                _LOGGER.exception("Unexpected error during Proton 2FA")
                errors["base"] = "unknown"
            else:
                return await self._async_after_second_factor()
        return self.async_show_form(
            step_id="totp",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_TOTP): TextSelector(
                        TextSelectorConfig(autocomplete="one-time-code")
                    )
                }
            ),
            errors=errors,
        )

    async def _async_after_second_factor(self) -> ConfigFlowResult:
        assert self._login is not None
        if self._login.two_password_mode:
            return self._show_mailbox_password_form({})
        errors: dict[str, str] = {}
        result = await self._async_unlock(self._password, errors)
        if result is not None:
            return result
        if errors.get("base") == "invalid_mailbox_password":
            # The login password does not unlock the keys: ask for the mailbox password.
            errors = {}
        return self._show_mailbox_password_form(errors)

    async def async_step_mailbox_password(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Accounts in two-password mode need their mailbox password to unlock keys."""
        errors: dict[str, str] = {}
        if user_input is not None:
            result = await self._async_unlock(user_input[CONF_MAILBOX_PASSWORD], errors)
            if result is not None:
                return result
        return self._show_mailbox_password_form(errors)

    def _show_mailbox_password_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="mailbox_password",
            data_schema=vol.Schema({vol.Required(CONF_MAILBOX_PASSWORD): PASSWORD_SELECTOR}),
            errors=errors,
        )

    async def _async_unlock(self, password: str, errors: dict[str, str]) -> ConfigFlowResult | None:
        assert self._client is not None
        try:
            await self._client.unlock(password)
            self._calendars = await self._client.list_calendars()
        except InvalidMailboxPassword:
            errors["base"] = "invalid_mailbox_password"
            return None
        except ProtonConnectionError:
            errors["base"] = "cannot_connect"
            return None
        except ProtonError:
            _LOGGER.exception("Unexpected error unlocking Proton keys")
            errors["base"] = "unknown"
            return None
        self._password = ""
        return await self._async_finish_auth()

    async def _async_finish_auth(self) -> ConfigFlowResult:
        assert self._client is not None and self._client.session is not None
        session = self._client.session
        await self.async_set_unique_id(session.user_id)
        if self.source == SOURCE_REAUTH:
            self._abort_if_unique_id_mismatch(reason="wrong_account")
            entry = self._get_reauth_entry()
            old = entry.data.get(CONF_SESSION)
            result = self.async_update_reload_and_abort(
                entry, data_updates={CONF_SESSION: session.as_dict()}
            )
            if old and old.get("uid") != session.uid:
                # Revoke the expired session so it does not linger in Proton's session list.
                await create_client(self.hass, Session.from_dict(old)).logout()
            return result
        self._abort_if_unique_id_configured()
        return await self.async_step_calendars()

    # -------------------------------------------------------------- calendars

    async def async_step_calendars(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick which calendars to add to Home Assistant."""
        assert self._client is not None and self._client.session is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            if not user_input.get(CONF_CALENDARS):
                errors["base"] = "no_calendars"
            else:
                return self.async_create_entry(
                    title=self._username,
                    data={
                        CONF_USERNAME: self._username,
                        CONF_SESSION: self._client.session.as_dict(),
                    },
                    options={
                        CONF_CALENDARS: user_input[CONF_CALENDARS],
                        CONF_LOOKAHEAD_DAYS: DEFAULT_LOOKAHEAD_DAYS,
                        CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL_MINUTES,
                        CONF_FILTERS: [],
                        CONF_SHOW_SIDEBAR_PANEL: DEFAULT_SHOW_SIDEBAR_PANEL,
                    },
                )
        if not self._calendars:
            return self.async_abort(reason="no_calendars_found")
        return self.async_show_form(
            step_id="calendars",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema({vol.Required(CONF_CALENDARS): _calendar_selector(self._calendars)}),
                {CONF_CALENDARS: [c.id for c in self._calendars if c.active]},
            ),
            errors=errors,
        )

    # ------------------------------------------------------------------ reauth

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """The stored session expired or was revoked."""
        self._username = entry_data.get(CONF_USERNAME, "")
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the password again."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._password = user_input[CONF_PASSWORD]
            result = await self._async_login(errors)
            if result is not None:
                return result
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): PASSWORD_SELECTOR}),
            description_placeholders={"username": self._username},
            errors=errors,
        )


class ProtonCalendarOptionsFlow(OptionsFlow):
    """Change calendar selection and polling."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry: ProtonCalendarConfigEntry = self.config_entry
        if user_input is not None:
            if not user_input.get(CONF_CALENDARS):
                errors["base"] = "no_calendars"
            else:
                return self.async_create_entry(
                    data={
                        CONF_CALENDARS: user_input[CONF_CALENDARS],
                        CONF_LOOKAHEAD_DAYS: int(user_input[CONF_LOOKAHEAD_DAYS]),
                        CONF_SCAN_INTERVAL: int(user_input[CONF_SCAN_INTERVAL]),
                        CONF_FILTERS: [
                            text for f in user_input.get(CONF_FILTERS, []) if (text := f.strip())
                        ],
                        CONF_SHOW_SIDEBAR_PANEL: user_input[CONF_SHOW_SIDEBAR_PANEL],
                    }
                )

        if entry.state is not ConfigEntryState.LOADED:
            return self.async_abort(reason="not_loaded")
        coordinator = entry.runtime_data
        try:
            calendars = await coordinator.client.list_calendars()
        except ProtonError:
            calendars = list(coordinator.all_calendars.values())
        if not calendars:
            return self.async_abort(reason="cannot_connect")

        schema = vol.Schema(
            {
                vol.Required(CONF_CALENDARS): _calendar_selector(calendars),
                vol.Required(CONF_LOOKAHEAD_DAYS): NumberSelector(
                    NumberSelectorConfig(
                        min=1, max=365, step=1, mode=NumberSelectorMode.BOX, unit_of_measurement="d"
                    )
                ),
                vol.Required(CONF_SCAN_INTERVAL): NumberSelector(
                    NumberSelectorConfig(
                        min=MIN_SCAN_INTERVAL_MINUTES,
                        max=1440,
                        step=1,
                        mode=NumberSelectorMode.BOX,
                        unit_of_measurement="min",
                    )
                ),
                vol.Optional(CONF_FILTERS): TextSelector(TextSelectorConfig(multiple=True)),
                vol.Required(CONF_SHOW_SIDEBAR_PANEL): BooleanSelector(),
            }
        )
        known = {c.id for c in calendars}
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                schema,
                {
                    CONF_CALENDARS: [
                        c for c in entry.options.get(CONF_CALENDARS, []) if c in known
                    ],
                    CONF_LOOKAHEAD_DAYS: entry.options.get(
                        CONF_LOOKAHEAD_DAYS, DEFAULT_LOOKAHEAD_DAYS
                    ),
                    CONF_SCAN_INTERVAL: entry.options.get(
                        CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL_MINUTES
                    ),
                    CONF_FILTERS: entry.options.get(CONF_FILTERS, []),
                    CONF_SHOW_SIDEBAR_PANEL: entry.options.get(
                        CONF_SHOW_SIDEBAR_PANEL, DEFAULT_SHOW_SIDEBAR_PANEL
                    ),
                },
            ),
            errors=errors,
        )
