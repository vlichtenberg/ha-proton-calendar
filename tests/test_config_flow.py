"""Tests for the Proton Calendar config flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.proton_calendar.const import (
    CONF_CALENDARS,
    CONF_MAILBOX_PASSWORD,
    CONF_SESSION,
    CONF_TOTP,
    DOMAIN,
)
from custom_components.proton_calendar.proton import (
    HumanVerificationFailed,
    HumanVerificationRequired,
    InvalidCredentials,
    InvalidMailboxPassword,
    InvalidTwoFactorCode,
    LoginResult,
    ProtonCalendar,
    Session,
)

CALENDARS = [
    ProtonCalendar("cal-1", "Personal", "#f00", "", 0, 1, "m1", "a1", "me@example.com"),
    ProtonCalendar("cal-2", "Work", "#0f0", "", 0, 1, "m2", "a1", "me@example.com"),
]


def _mock_client(two_factor: bool = False, two_password: bool = False) -> MagicMock:
    client = MagicMock()
    client.session = Session("uid", "access", "refresh", user_id="user-1")

    async def unlock(password: str) -> None:
        client.session.key_passphrase = "derived"

    client.login = AsyncMock(
        return_value=LoginResult(
            client.session, two_factor_required=two_factor, two_password_mode=two_password
        )
    )
    client.submit_totp = AsyncMock()
    client.unlock = AsyncMock(side_effect=unlock)
    client.list_calendars = AsyncMock(return_value=CALENDARS)
    client.logout = AsyncMock()
    return client


@pytest.fixture
def mock_setup_entry():
    with patch("custom_components.proton_calendar.async_setup_entry", return_value=True) as mock:
        yield mock


async def _start(hass: HomeAssistant, client: MagicMock) -> dict:
    with patch("custom_components.proton_calendar.config_flow.create_client", return_value=client):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "user"
        return await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_USERNAME: "me@example.com", CONF_PASSWORD: "pw"}
        )


async def test_full_flow_with_totp(hass: HomeAssistant, mock_setup_entry) -> None:
    client = _mock_client(two_factor=True)
    result = await _start(hass, client)
    assert result["step_id"] == "totp"

    client.submit_totp.side_effect = InvalidTwoFactorCode("bad")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOTP: "000000"}
    )
    assert result["errors"] == {"base": "invalid_2fa"}

    client.submit_totp.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOTP: "123456"}
    )
    assert result["step_id"] == "calendars"
    client.unlock.assert_awaited_once_with("pw")

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_CALENDARS: ["cal-2"]}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "me@example.com"
    assert result["result"].unique_id == "user-1"
    assert result["data"][CONF_SESSION]["key_passphrase"] == "derived"
    assert CONF_PASSWORD not in result["data"]
    assert result["options"][CONF_CALENDARS] == ["cal-2"]


async def test_invalid_credentials(hass: HomeAssistant) -> None:
    client = _mock_client()
    client.login.side_effect = InvalidCredentials("nope")
    result = await _start(hass, client)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}


async def test_human_verification_then_success(hass: HomeAssistant, mock_setup_entry) -> None:
    client = _mock_client()
    login_result = client.login.return_value
    client.login.side_effect = [HumanVerificationRequired("hv-1", ["captcha"]), login_result]
    with patch("custom_components.proton_calendar.config_flow.create_client", return_value=client):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_USERNAME: "me@example.com", CONF_PASSWORD: "pw"}
        )
        assert result["step_id"] == "human_verification"
        assert "hv-1" in result["description_placeholders"]["url"]
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "calendars"
    assert client.login.await_args.args == ("me@example.com", "pw", "hv-1")


async def test_rejected_verification_requests_new_challenge(
    hass: HomeAssistant, mock_setup_entry
) -> None:
    client = _mock_client()
    login_result = client.login.return_value
    client.login.side_effect = [
        HumanVerificationRequired("hv-1", ["captcha"]),
        HumanVerificationFailed("CAPTCHA validation failed"),
        HumanVerificationRequired("hv-2", ["captcha"]),
        login_result,
    ]
    with patch("custom_components.proton_calendar.config_flow.create_client", return_value=client):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_USERNAME: "me@example.com", CONF_PASSWORD: "pw"}
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["step_id"] == "human_verification"
        assert result["errors"] == {"base": "hv_failed"}
        assert "hv-2" in result["description_placeholders"]["url"]
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "calendars"
    assert client.login.await_args.args == ("me@example.com", "pw", "hv-2")


async def test_two_password_mode(hass: HomeAssistant, mock_setup_entry) -> None:
    client = _mock_client(two_password=True)
    result = await _start(hass, client)
    assert result["step_id"] == "mailbox_password"
    client.unlock.assert_not_awaited()

    original = client.unlock.side_effect
    client.unlock.side_effect = InvalidMailboxPassword("wrong")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MAILBOX_PASSWORD: "wrong"}
    )
    assert result["errors"] == {"base": "invalid_mailbox_password"}

    client.unlock.side_effect = original
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MAILBOX_PASSWORD: "mailbox"}
    )
    assert result["step_id"] == "calendars"
    client.unlock.assert_awaited_with("mailbox")


async def test_already_configured(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id="user-1").add_to_hass(hass)
    result = await _start(hass, _mock_client())
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reauth(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id="user-1",
        data={
            CONF_USERNAME: "me@example.com",
            CONF_SESSION: Session("old", "a", "r", "k", "user-1").as_dict(),
        },
        options={CONF_CALENDARS: ["cal-1"]},
    )
    entry.add_to_hass(hass)
    client = _mock_client()
    with (
        patch("custom_components.proton_calendar.config_flow.create_client", return_value=client),
        patch("custom_components.proton_calendar.async_setup_entry", return_value=True),
    ):
        result = await entry.start_reauth_flow(hass)
        assert result["step_id"] == "reauth_confirm"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_PASSWORD: "new-pw"}
        )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_SESSION]["uid"] == "uid"
    assert entry.data[CONF_SESSION]["key_passphrase"] == "derived"
    client.logout.assert_awaited()  # the old session is revoked
