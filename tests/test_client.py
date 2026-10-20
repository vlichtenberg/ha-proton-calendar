"""Tests for the Proton API client."""

from __future__ import annotations

import base64

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import pytest
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
    AiohttpClientMockResponse,
)

from custom_components.proton_calendar.proton import client as client_mod
from custom_components.proton_calendar.proton.client import (
    API_URL,
    VERSION_URL,
    HumanVerificationRequired,
    ProtonAuthError,
    ProtonClient,
    Session,
)
from custom_components.proton_calendar.proton.events import merge_cards

from .conftest import load_fixture_bytes, load_fixture_text


def _client(hass: HomeAssistant, **kwargs) -> ProtonClient:
    return ProtonClient(
        async_get_clientsession(hass),
        session=Session("uid-1", "access-1", "refresh-1", key_passphrase="test-pass"),
        executor=hass.async_add_executor_job,
        **kwargs,
    )


def test_full_decryption_chain() -> None:
    """User key -> address key token -> calendar passphrase -> calendar key -> event."""
    user = {
        "ID": "u",
        "Keys": [{"ID": "uk", "PrivateKey": load_fixture_text("ecc_secret.asc"), "Active": 1}],
    }
    addresses = [
        {
            "ID": "addr-1",
            "Email": "Me@Example.com",
            "Keys": [
                {
                    "ID": "ak",
                    "PrivateKey": load_fixture_text("rsa_secret.asc"),
                    "Token": load_fixture_text("address_token.asc"),
                    "Active": 1,
                }
            ],
        }
    ]
    keyring = client_mod._unlock_account_keys(user, addresses, b"test-pass")
    assert keyring.emails == {"me@example.com": "addr-1"}

    bootstrap = {
        "Keys": [{"ID": "ck", "PrivateKey": load_fixture_text("ecc_secret.asc"), "Flags": 3}],
        "Passphrase": {
            "MemberPassphrases": [
                {"MemberID": "member-1", "Passphrase": load_fixture_text("calendar_passphrase.asc")}
            ]
        },
    }
    cal_keys = client_mod._CalendarKeys(
        keys=client_mod._unlock_calendar_keys(bootstrap, "member-1", keyring.addresses["addr-1"])
    )

    message = load_fixture_bytes("event_shared.gpg")
    key_packet, data_packet = message[:96], message[96:]
    raw_event = {
        "ID": "ev-1",
        "CalendarID": "cal-1",
        "SharedKeyPacket": base64.b64encode(key_packet).decode(),
        "SharedEvents": [
            {
                "Type": 2,
                "Data": "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:enc-1\r\nDTSTART:20261020T180000Z\r\nEND:VEVENT\r\nEND:VCALENDAR",
            },
            {"Type": 3, "Data": base64.b64encode(data_packet).decode()},
        ],
        "CalendarEvents": [
            {
                "Type": 0,
                "Data": "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSTATUS:CONFIRMED\r\nEND:VEVENT\r\nEND:VCALENDAR",
            }
        ],
    }
    broken_event = {
        **raw_event,
        "ID": "ev-2",
        "SharedKeyPacket": base64.b64encode(b"\x84\x01\x00").decode(),
    }

    [cards] = client_mod._decrypt_events([raw_event, broken_event], cal_keys, keyring)
    merged = merge_cards(cards.cards)
    assert merged["SUMMARY"][0].value == "Encrypted dinner"
    assert merged["LOCATION"][0].value == "Secret place"
    assert merged["STATUS"][0].value == "CONFIRMED"


def test_wrong_stored_passphrase_requires_reauth() -> None:
    user = {"ID": "u", "Keys": [{"ID": "uk", "PrivateKey": load_fixture_text("ecc_secret.asc")}]}
    with pytest.raises(ProtonAuthError):
        client_mod._unlock_account_keys(user, [], b"wrong")


async def test_access_token_refresh_on_401(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    updates: list[Session] = []
    calls = {"users": 0}

    async def users(method, url, data):
        calls["users"] += 1
        if calls["users"] == 1:
            return AiohttpClientMockResponse(
                method, url, status=401, json={"Code": 401, "Error": "expired"}
            )
        return AiohttpClientMockResponse(method, url, json={"Code": 1000, "User": {"ID": "user-1"}})

    aioclient_mock.get(f"{API_URL}/core/v4/users", side_effect=users)
    aioclient_mock.post(
        f"{API_URL}/auth/v4/refresh",
        json={"Code": 1000, "AccessToken": "access-2", "RefreshToken": "refresh-2"},
    )
    client = _client(hass, on_session_update=updates.append)
    assert await client.get_user_id() == "user-1"
    assert client.session.access_token == "access-2"
    assert client.session.refresh_token == "refresh-2"
    assert updates and updates[-1].refresh_token == "refresh-2"
    assert aioclient_mock.mock_calls[-1][3]["Authorization"] == "Bearer access-2"


async def test_expired_refresh_token_raises_auth_error(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    aioclient_mock.get(
        f"{API_URL}/core/v4/users", status=401, json={"Code": 401, "Error": "expired"}
    )
    aioclient_mock.post(
        f"{API_URL}/auth/v4/refresh",
        status=422,
        json={"Code": 10013, "Error": "Invalid refresh token"},
    )
    with pytest.raises(ProtonAuthError):
        await _client(hass).get_user_id()


async def test_outdated_app_version_is_replaced(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    async def users(method, url, data):
        if aioclient_mock.mock_calls[-1][3]["x-pm-appversion"] == "web-calendar@1.0.0":
            return AiohttpClientMockResponse(
                method, url, status=400, json={"Code": 5003, "Error": "old"}
            )
        return AiohttpClientMockResponse(method, url, json={"Code": 1000, "User": {"ID": "user-1"}})

    aioclient_mock.get(f"{API_URL}/core/v4/users", side_effect=users)
    aioclient_mock.get(VERSION_URL, json={"version": "5.0.999.1"})
    client = _client(hass, app_version="web-calendar@1.0.0")
    assert await client.get_user_id() == "user-1"
    assert client.app_version == "web-calendar@5.0.999.1"


async def test_human_verification_is_reported(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    aioclient_mock.post(
        f"{API_URL}/core/v4/auth/info",
        status=422,
        json={
            "Code": 9001,
            "Error": "Human verification required",
            "Details": {
                "HumanVerificationToken": "hv-token",
                "HumanVerificationMethods": ["captcha"],
            },
        },
    )
    client = ProtonClient(async_get_clientsession(hass), executor=hass.async_add_executor_job)
    with pytest.raises(HumanVerificationRequired) as err:
        await client.login("me@example.com", "pw")
    assert err.value.token == "hv-token"
    assert "token=hv-token" in err.value.url


def test_human_verification_url_is_encoded() -> None:
    url = HumanVerificationRequired("a+b/c=", ["captcha"]).url
    assert url.endswith("token=a%2Bb%2Fc%3D")


async def test_list_calendars_uses_member_metadata(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    aioclient_mock.get(
        f"{API_URL}/calendar/v1",
        json={
            "Code": 1000,
            "Calendars": [
                {
                    "ID": "cal-1",
                    "Type": 0,
                    "Members": [
                        {
                            "ID": "m1",
                            "AddressID": "a1",
                            "Name": "Family",
                            "Color": "#ff0000",
                            "Flags": 1,
                            "Email": "me@example.com",
                        }
                    ],
                },
                {
                    "ID": "cal-2",
                    "Type": 1,
                    "Members": [{"ID": "m2", "Name": "Holidays", "Flags": 0}],
                },
            ],
        },
    )
    calendars = await _client(hass).list_calendars()
    assert [(c.id, c.name, c.member_id, c.active) for c in calendars] == [
        ("cal-1", "Family", "m1", True),
        ("cal-2", "Holidays", "m2", True),
    ]


async def test_fetch_raw_events_pages_and_dedupes(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    async def events(method, url, data):
        query_type = int(url.query["Type"])
        page = int(url.query["Page"])
        if query_type == 0 and page == 0:
            batch = [{"ID": f"e{i}"} for i in range(client_mod.EVENT_PAGE_SIZE)]
        elif query_type == 0 and page == 1:
            batch = [{"ID": "last"}]
        elif query_type == 1:
            batch = [{"ID": "e0"}]  # duplicate across query types
        else:
            batch = []
        return AiohttpClientMockResponse(method, url, json={"Code": 1000, "Events": batch})

    aioclient_mock.get(f"{API_URL}/calendar/v1/cal-1/events", side_effect=events)
    raw = await _client(hass).fetch_raw_events("cal-1", 0, 100, "Europe/Amsterdam")
    assert len(raw) == client_mod.EVENT_PAGE_SIZE + 1
