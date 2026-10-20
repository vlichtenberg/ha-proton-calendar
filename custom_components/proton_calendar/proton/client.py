"""Async client for the parts of the Proton API needed to read calendars."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import hmac
import logging
import secrets
from typing import Any
from urllib.parse import quote

import aiohttp

from . import pgp, srp
from .events import EventCards

_LOGGER = logging.getLogger(__name__)

API_URL = "https://calendar.proton.me/api"
VERSION_URL = "https://calendar.proton.me/assets/version.json"
DEFAULT_APP_VERSION = "web-calendar@5.0.136.4"

CODE_SUCCESS = 1000
CODE_MULTI = 1001
CODE_APP_VERSION_BAD = 5003
CODE_APP_VERSION_INVALID = 5002
CODE_WRONG_PASSWORD = 8002
CODE_HUMAN_VERIFICATION = 9001
CODE_REFRESH_TOKEN_INVALID = 10013
CODE_HUMAN_VERIFICATION_FAILED = 12087

TWO_FA_TOTP = 1
TWO_FA_FIDO2 = 2
TWO_FA_BOTH = 3

PASSWORD_MODE_TWO = 2

EVENT_PAGE_SIZE = 100
# PartDayInsideWindow, PartDayBeforeWindow, FullDayInsideWindow, FullDayBeforeWindow
EVENT_QUERY_TYPES = (0, 1, 2, 3)

CALENDAR_FLAG_ACTIVE = 1
CALENDAR_KEY_FLAG_PRIMARY = 2

TokenCallback = Callable[["Session"], Awaitable[None] | None]


class ProtonError(Exception):
    """Base error for the Proton client."""


class ProtonConnectionError(ProtonError):
    """The Proton API could not be reached or is rate limiting."""


class ProtonApiError(ProtonError):
    """The Proton API returned an error response."""

    def __init__(self, status: int, code: int, message: str, details: Any = None) -> None:
        super().__init__(f"{message} (code {code}, HTTP {status})")
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


class ProtonAuthError(ProtonError):
    """Credentials or session are no longer valid; the user must log in again."""


class InvalidCredentials(ProtonAuthError):
    """Username or password is wrong."""


class InvalidTwoFactorCode(ProtonAuthError):
    """The TOTP code was rejected."""


class InvalidMailboxPassword(ProtonAuthError):
    """The (mailbox) password does not unlock the account keys."""


class UnsupportedTwoFactor(ProtonAuthError):
    """The account only allows security keys (FIDO2), which cannot be used here."""


class HumanVerificationRequired(ProtonError):
    """Proton wants a CAPTCHA to be solved before allowing the login."""

    def __init__(self, token: str, methods: list[str]) -> None:
        super().__init__("Human verification required")
        self.token = token
        self.methods = methods

    @property
    def url(self) -> str:
        """Web page where the user can solve the challenge."""
        return f"https://verify.proton.me/?methods=captcha&token={quote(self.token, safe='')}"


class HumanVerificationFailed(ProtonError):
    """Proton did not accept the solved CAPTCHA; the challenge token is spent."""


@dataclass
class Session:
    """Persistable session state: the local credential store for one account."""

    uid: str
    access_token: str
    refresh_token: str
    key_passphrase: str | None = None
    user_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "key_passphrase": self.key_passphrase,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            uid=data["uid"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            key_passphrase=data.get("key_passphrase"),
            user_id=data.get("user_id"),
        )


@dataclass
class LoginResult:
    """Outcome of the password step of a login."""

    session: Session
    two_factor_required: bool
    two_password_mode: bool


@dataclass
class ProtonCalendar:
    """A calendar the account is a member of."""

    id: str
    name: str
    color: str
    description: str
    type: int
    flags: int
    member_id: str | None
    address_id: str | None
    email: str | None

    @property
    def active(self) -> bool:
        return bool(self.flags & CALENDAR_FLAG_ACTIVE) or self.flags == 0


@dataclass
class _CalendarKeys:
    keys: list[pgp.SecretKey]
    address_id: str | None = None


@dataclass
class _Keyring:
    user: list[pgp.SecretKey] = field(default_factory=list)
    addresses: dict[str, list[pgp.SecretKey]] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)


class ProtonClient:
    """Thin async wrapper around the Proton API."""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        session: Session | None = None,
        on_session_update: TokenCallback | None = None,
        app_version: str = DEFAULT_APP_VERSION,
        executor: Callable[..., Awaitable[Any]] | None = None,
    ) -> None:
        self._http = websession
        self.session = session
        self.on_session_update = on_session_update
        self.app_version = app_version
        self._refresh_lock = asyncio.Lock()
        self._keys_lock = asyncio.Lock()
        self._keyring: _Keyring | None = None
        self._calendar_keys: dict[str, _CalendarKeys] = {}
        self._executor = executor or _default_executor

    # ------------------------------------------------------------------ http

    def _headers(self, authenticated: bool) -> dict[str, str]:
        headers = {
            "x-pm-appversion": self.app_version,
            "Accept": "application/vnd.protonmail.v1+json",
        }
        if authenticated and self.session:
            headers["x-pm-uid"] = self.session.uid
            headers["Authorization"] = f"Bearer {self.session.access_token}"
        return headers

    async def _raw_request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = self._headers(authenticated)
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with self._http.request(
                method,
                f"{API_URL}{path}",
                json=json,
                params=params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status in (429, 503):
                    raise ProtonConnectionError(
                        f"Proton API is rate limiting or unavailable (HTTP {resp.status})"
                    )
                try:
                    data = await resp.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError) as err:
                    raise ProtonConnectionError(
                        f"Unexpected response from Proton (HTTP {resp.status})"
                    ) from err
                status = resp.status
        except (aiohttp.ClientError, TimeoutError) as err:
            raise ProtonConnectionError(f"Cannot reach Proton: {err}") from err

        if not isinstance(data, dict):
            raise ProtonConnectionError("Unexpected response from Proton")
        code = data.get("Code", 0)
        if status >= 400 or code not in (CODE_SUCCESS, CODE_MULTI):
            raise ProtonApiError(
                status, code, data.get("Error", "Unknown error"), data.get("Details")
            )
        return data

    async def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Request with app-version healing and transparent token refresh."""
        retried_version = False
        retried_auth = False
        while True:
            try:
                return await self._raw_request(method, path, authenticated=authenticated, **kwargs)
            except ProtonApiError as err:
                if (
                    err.code in (CODE_APP_VERSION_BAD, CODE_APP_VERSION_INVALID)
                    and not retried_version
                ):
                    retried_version = True
                    await self._update_app_version()
                    continue
                if err.status == 401 and authenticated and self.session and not retried_auth:
                    retried_auth = True
                    await self.refresh()
                    continue
                if err.code == CODE_HUMAN_VERIFICATION:
                    raise HumanVerificationRequired(
                        err.details.get("HumanVerificationToken", ""),
                        err.details.get("HumanVerificationMethods", []),
                    ) from err
                raise

    async def _update_app_version(self) -> None:
        """Proton rejects outdated clients; adopt the current web-calendar version."""
        try:
            async with self._http.get(VERSION_URL, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError, ValueError) as err:
            raise ProtonConnectionError("Cannot determine current Proton app version") from err
        version = data.get("version") if isinstance(data, dict) else None
        if not version:
            raise ProtonConnectionError("Cannot determine current Proton app version")
        self.app_version = f"web-calendar@{version}"
        _LOGGER.debug("Switched Proton app version to %s", self.app_version)

    async def _notify_session(self) -> None:
        if self.on_session_update and self.session:
            result = self.on_session_update(self.session)
            if asyncio.iscoroutine(result):
                await result

    # ------------------------------------------------------------------ auth

    async def login(
        self,
        username: str,
        password: str,
        hv_token: str | None = None,
        hv_type: str = "captcha",
    ) -> LoginResult:
        """Run the SRP password step. Raises HumanVerificationRequired if needed."""
        info = await self._request(
            "POST", "/core/v4/auth/info", json={"Username": username}, authenticated=False
        )
        proofs = await self._executor(
            srp.generate_proofs,
            info["Version"],
            password.encode("utf-8"),
            info["Salt"],
            info["Modulus"],
            info["ServerEphemeral"],
        )
        headers = None
        if hv_token:
            headers = {
                "x-pm-human-verification-token": hv_token,
                "x-pm-human-verification-token-type": hv_type,
            }
        try:
            auth = await self._request(
                "POST",
                "/core/v4/auth",
                json={
                    "Username": username,
                    "ClientEphemeral": base64.b64encode(proofs.client_ephemeral).decode(),
                    "ClientProof": base64.b64encode(proofs.client_proof).decode(),
                    "SRPSession": info["SRPSession"],
                },
                authenticated=False,
                extra_headers=headers,
            )
        except ProtonApiError as err:
            if err.code == CODE_HUMAN_VERIFICATION_FAILED:
                raise HumanVerificationFailed(err.message) from err
            if err.code == CODE_WRONG_PASSWORD or err.status == 422:
                raise InvalidCredentials(err.message) from err
            raise

        server_proof = base64.b64decode(auth.get("ServerProof", ""))
        if not hmac.compare_digest(server_proof, proofs.expected_server_proof):
            raise ProtonError("Server proof mismatch; refusing to continue")

        two_fa = (auth.get("2FA") or {}).get("Enabled", 0)
        if two_fa == TWO_FA_FIDO2:
            raise UnsupportedTwoFactor(
                "This account only has a security key as second factor; add an authenticator app"
            )
        self.session = Session(
            uid=auth["UID"],
            access_token=auth["AccessToken"],
            refresh_token=auth["RefreshToken"],
            user_id=auth.get("UserID"),
        )
        return LoginResult(
            session=self.session,
            two_factor_required=bool(two_fa & TWO_FA_TOTP),
            two_password_mode=auth.get("PasswordMode") == PASSWORD_MODE_TWO,
        )

    async def submit_totp(self, code: str) -> None:
        """Complete the second factor with a TOTP code."""
        try:
            await self._request("POST", "/core/v4/auth/2fa", json={"TwoFactorCode": code.strip()})
        except ProtonApiError as err:
            if err.status in (401, 422) or err.code == CODE_WRONG_PASSWORD:
                raise InvalidTwoFactorCode(err.message) from err
            raise

    async def unlock(self, mailbox_password: str) -> None:
        """Derive and verify the key passphrase from the (mailbox) password."""
        salts = (await self._request("GET", "/core/v4/keys/salts"))["KeySalts"]
        user = (await self._request("GET", "/core/v4/users"))["User"]
        salt_by_key = {s["ID"]: s.get("KeySalt") for s in salts}
        primary = next((k for k in user["Keys"] if k.get("Primary")), user["Keys"][0])
        key_salt = salt_by_key.get(primary["ID"])
        passphrase = await self._executor(
            srp.mailbox_password,
            mailbox_password.encode("utf-8"),
            base64.b64decode(key_salt) if key_salt else b"",
        )
        try:
            await self._executor(pgp.unlock_keys, primary["PrivateKey"], passphrase)
        except pgp.PGPError as err:
            raise InvalidMailboxPassword("Password does not unlock the account keys") from err
        assert self.session is not None
        self.session.key_passphrase = passphrase.decode("ascii")
        self.session.user_id = user["ID"]
        self._keyring = None
        await self._notify_session()

    async def refresh(self) -> None:
        """Exchange the refresh token for a new token pair."""
        if self.session is None:
            raise ProtonAuthError("Not logged in")
        old_access = self.session.access_token
        async with self._refresh_lock:
            if self.session.access_token != old_access:
                return  # another task already refreshed
            try:
                data = await self._raw_request(
                    "POST",
                    "/auth/v4/refresh",
                    json={
                        "UID": self.session.uid,
                        "RefreshToken": self.session.refresh_token,
                        "ResponseType": "token",
                        "GrantType": "refresh_token",
                        "RedirectURI": "https://protonmail.ch",
                        "State": secrets.token_urlsafe(24),
                    },
                    authenticated=False,
                    extra_headers={"x-pm-uid": self.session.uid},
                )
            except ProtonApiError as err:
                if err.status in (400, 401, 422) or err.code == CODE_REFRESH_TOKEN_INVALID:
                    raise ProtonAuthError("Proton session expired") from err
                raise
            self.session.access_token = data["AccessToken"]
            self.session.refresh_token = data["RefreshToken"]
            await self._notify_session()

    async def logout(self) -> None:
        """Revoke the session server-side."""
        if self.session is None:
            return
        try:
            await self._raw_request("DELETE", "/core/v4/auth")
        except ProtonError as err:
            _LOGGER.debug("Logout failed: %s", err)

    # ------------------------------------------------------------------ keys

    async def _get_keyring(self) -> _Keyring:
        async with self._keys_lock:
            if self._keyring is not None:
                return self._keyring
            if not self.session or not self.session.key_passphrase:
                raise ProtonAuthError("Key passphrase missing; log in again")
            user = (await self._request("GET", "/core/v4/users"))["User"]
            addresses = (await self._request("GET", "/core/v4/addresses"))["Addresses"]
            passphrase = self.session.key_passphrase.encode("ascii")
            self._keyring = await self._executor(_unlock_account_keys, user, addresses, passphrase)
            return self._keyring

    async def _get_calendar_keys(self, calendar: ProtonCalendar) -> _CalendarKeys:
        cached = self._calendar_keys.get(calendar.id)
        if cached is not None:
            return cached
        keyring = await self._get_keyring()
        boot = await self._request("GET", f"/calendar/v2/{calendar.id}/bootstrap")
        members = boot.get("Members") or []
        own = [m for m in members if m.get("AddressID") in keyring.addresses]
        if not own and calendar.member_id:
            own = [m for m in members if m.get("ID") == calendar.member_id]
        if not own:
            raise ProtonError(f"No own membership found for calendar {calendar.name}")
        member = own[0]
        address_id = member.get("AddressID") or keyring.emails.get(member.get("Email", ""))
        keys = await self._executor(
            _unlock_calendar_keys,
            boot,
            member["ID"],
            keyring.addresses.get(address_id, [])
            or [k for ks in keyring.addresses.values() for k in ks],
        )
        result = _CalendarKeys(keys=keys, address_id=address_id)
        self._calendar_keys[calendar.id] = result
        return result

    def clear_key_cache(self) -> None:
        """Forget unlocked keys (e.g. after keys were rotated)."""
        self._keyring = None
        self._calendar_keys.clear()

    # ------------------------------------------------------------- calendars

    async def get_user_id(self) -> str:
        user = (await self._request("GET", "/core/v4/users"))["User"]
        return user["ID"]

    async def list_calendars(self) -> list[ProtonCalendar]:
        data = await self._request("GET", "/calendar/v1", params={"ReturnFlags": 1})
        calendars = []
        for cal in data.get("Calendars", []):
            members = cal.get("Members") or [{}]
            member = members[0]
            calendars.append(
                ProtonCalendar(
                    id=cal["ID"],
                    name=member.get("Name") or cal.get("Name") or "Proton Calendar",
                    color=member.get("Color") or cal.get("Color") or "#8080FF",
                    description=member.get("Description") or cal.get("Description") or "",
                    type=cal.get("Type", 0),
                    flags=member.get("Flags", cal.get("Flags", 0)) or 0,
                    member_id=member.get("ID"),
                    address_id=member.get("AddressID"),
                    email=member.get("Email") or cal.get("Email"),
                )
            )
        return calendars

    async def fetch_raw_events(
        self, calendar_id: str, start: int, end: int, timezone: str
    ) -> list[dict[str, Any]]:
        """Fetch encrypted events overlapping the window [start, end] (unix seconds)."""
        events: dict[str, dict[str, Any]] = {}
        for query_type in EVENT_QUERY_TYPES:
            page = 0
            while True:
                data = await self._request(
                    "GET",
                    f"/calendar/v1/{calendar_id}/events",
                    params={
                        "Start": start,
                        "End": end,
                        "Timezone": timezone,
                        "Type": query_type,
                        "Page": page,
                        "PageSize": EVENT_PAGE_SIZE,
                    },
                )
                batch = data.get("Events", [])
                for event in batch:
                    events[event["ID"]] = event
                if len(batch) < EVENT_PAGE_SIZE:
                    break
                page += 1
        return list(events.values())

    async def fetch_event_cards(
        self, calendar: ProtonCalendar, start: int, end: int, timezone: str
    ) -> list[EventCards]:
        """Fetch and decrypt the iCalendar cards of all events in a window."""
        raw = await self.fetch_raw_events(calendar.id, start, end, timezone)
        if not raw:
            return []
        cal_keys = await self._get_calendar_keys(calendar)
        keyring = await self._get_keyring()
        return await self._executor(_decrypt_events, raw, cal_keys, keyring)


async def _default_executor(func: Callable[..., Any], *args: Any) -> Any:
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


# ----------------------------------------------------------- sync crypto helpers


def _unlock_account_keys(
    user: dict[str, Any], addresses: list[dict[str, Any]], passphrase: bytes
) -> _Keyring:
    keyring = _Keyring()
    for key in user.get("Keys", []):
        if key.get("Active", 1) == 0:
            continue
        try:
            keyring.user.extend(pgp.unlock_keys(key["PrivateKey"], passphrase))
        except pgp.PGPError as err:
            _LOGGER.debug("Cannot unlock user key %s: %s", key.get("ID"), err)
    if not keyring.user:
        raise ProtonAuthError("Stored key passphrase no longer unlocks the account keys")

    for address in addresses:
        unlocked: list[pgp.SecretKey] = []
        for key in address.get("Keys", []):
            if key.get("Active", 1) == 0:
                continue
            try:
                secret = passphrase
                if key.get("Token"):
                    secret = pgp.decrypt_message(key["Token"], keyring.user)
                unlocked.extend(pgp.unlock_keys(key["PrivateKey"], secret))
            except pgp.PGPError as err:
                _LOGGER.debug("Cannot unlock address key %s: %s", key.get("ID"), err)
        if unlocked:
            keyring.addresses[address["ID"]] = unlocked
            keyring.emails[address.get("Email", "").lower()] = address["ID"]
    return keyring


def _unlock_calendar_keys(
    bootstrap: dict[str, Any], member_id: str, address_keys: list[pgp.SecretKey]
) -> list[pgp.SecretKey]:
    member_passphrases = (bootstrap.get("Passphrase") or {}).get("MemberPassphrases", [])
    entry = next((p for p in member_passphrases if p.get("MemberID") == member_id), None)
    if entry is None:
        raise ProtonError("No calendar passphrase for this member")
    passphrase = pgp.decrypt_message(entry["Passphrase"], address_keys)
    keys: list[pgp.SecretKey] = []
    for key in bootstrap.get("Keys", []):
        try:
            keys.extend(pgp.unlock_keys(key["PrivateKey"], passphrase))
        except pgp.PGPError as err:
            _LOGGER.debug("Cannot unlock calendar key %s: %s", key.get("ID"), err)
    if not keys:
        raise ProtonError("Could not unlock any calendar key")
    return keys


def _decrypt_part(part: dict[str, Any], key_packet: bytes | None, keys: list[pgp.SecretKey]) -> str:
    data = part.get("Data") or ""
    if part.get("Type", 0) & 1:
        if key_packet is not None:
            return pgp.decrypt_split(key_packet, base64.b64decode(data), keys).decode("utf-8")
        return pgp.decrypt_message(data, keys).decode("utf-8")
    return data


def _decrypt_events(
    raw_events: list[dict[str, Any]], cal_keys: _CalendarKeys, keyring: _Keyring
) -> list[EventCards]:
    results: list[EventCards] = []
    for event in raw_events:
        try:
            shared_kp = event.get("SharedKeyPacket")
            shared_keys = cal_keys.keys
            if not shared_kp and event.get("AddressKeyPacket"):
                shared_kp = event["AddressKeyPacket"]
                shared_keys = keyring.addresses.get(event.get("AddressID") or "", []) or [
                    k for ks in keyring.addresses.values() for k in ks
                ]
            shared_packet = base64.b64decode(shared_kp) if shared_kp else None
            calendar_kp = event.get("CalendarKeyPacket")
            calendar_packet = base64.b64decode(calendar_kp) if calendar_kp else shared_packet

            cards = [
                _decrypt_part(p, shared_packet, shared_keys)
                for p in event.get("SharedEvents") or []
            ]
            cards += [
                _decrypt_part(p, calendar_packet, cal_keys.keys if calendar_kp else shared_keys)
                for p in event.get("CalendarEvents") or []
            ]
            results.append(
                EventCards(
                    event_id=event["ID"],
                    calendar_id=event.get("CalendarID", ""),
                    cards=cards,
                )
            )
        except (pgp.PGPError, ValueError, KeyError) as err:
            _LOGGER.warning(
                "Skipping event %s that could not be decrypted: %s", event.get("ID"), err
            )
    return results
