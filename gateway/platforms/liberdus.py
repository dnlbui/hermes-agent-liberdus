"""Liberdus Gateway platform adapter.

Polls a local liberdusd daemon API for redacted inbound events and sends
Hermes replies back through the daemon's controlled /send-requests endpoint.
The adapter never handles Liberdus private keys, signing payloads, seeds, or
full transaction JSON; those stay inside liberdusd.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

import httpx

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, ProcessingOutcome, SendResult
from gateway.session import SessionSource

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_MS = 15000
MIN_POLL_INTERVAL_MS = 500
DEFAULT_EVENTS_PAGE_SIZE = 50
MAX_EVENTS_PAGE_SIZE = 100
LIBERDUS_OUTBOUND_MESSAGE_MAX_BYTES = 1000

_PROCESSING_REACTION = "👀"
_SUCCESS_REACTION = "✅"
_FAILURE_REACTION = "❌"
_CANCELLED_REACTION = "❌"

_ALLOWED_PROFILES = {"dbp", "test"}
_ALLOWED_POLICY_MODES = {"full", "restricted-chat-only"}
_ALLOWED_DEV_ORIGINS = {"https://dev.liberdus.com:3030"}
_EXACT_DEV_INJECT = "https://dev.liberdus.com:3030/inject"
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

_SECRET_KEY_RE = re.compile(
    r"(private|passphrase|pq[_-]?seed|seed|recovery|ciphertext|signed[_-]?tx|raw[_-]?tx(?:[_-]?json)?|payload[_-]?json|secret)",
    re.IGNORECASE,
)
_FORBIDDEN_VALUE_RE = re.compile(
    r"SENTINEL_(?:PRIVATE_KEY|PQ_SEED|CIPHERTEXT|SIGNED_TX|PASSPHRASE)",
    re.IGNORECASE,
)
_FREEFORM_SECRET_RE = re.compile(
    r"\b(private.?key|pq.?seed|recovery(?:Secret)?|mnemonic|ciphertext|passphrase|signed[_-]?tx|raw[_-]?tx(?:[_-]?json)?|payload[_-]?json)\b\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s,;)}\]]+)",
    re.IGNORECASE,
)


def _bool_env(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _coerce_int(value: Any, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _split_allowlist(value: Any) -> list[str]:
    """Normalize comma/newline-separated config values into stable tokens."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = re.split(r"[,\n]", value)
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    result: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        result.append(token)
        seen.add(token)
    return result


def _allowlist_set(value: Any) -> set[str] | None:
    items = _split_allowlist(value)
    return set(items) if items else None


def _configured_http_url() -> str | None:
    """Return the local HTTP endpoint, accepting LIBERDUS_HTTP_URL as the final public knob.

    LIBERDUS_API_URL remains accepted for compatibility with the daemon spec and
    older runbooks.  If both names are set to different values, fail closed.
    """
    http_url = (os.getenv("LIBERDUS_HTTP_URL") or "").strip()
    api_url = (os.getenv("LIBERDUS_API_URL") or "").strip()
    if http_url and api_url and http_url != api_url:
        return "__conflicting_liberdus_http_url__"
    return http_url or api_url or None


def _configured_counterparty_profiles() -> list[str] | None:
    profiles = _split_allowlist(os.getenv("LIBERDUS_COUNTERPARTY_PROFILES"))
    if not profiles:
        return None
    normalized = [profile.lower() for profile in profiles]
    if any(profile not in _ALLOWED_PROFILES for profile in normalized):
        return []
    return normalized


def _is_loopback_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() in _LOOPBACK_HOSTS


def _scrub_text(value: str) -> str:
    text = _FORBIDDEN_VALUE_RE.sub("[redacted]", value)
    return _FREEFORM_SECRET_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)


def _stable_adapter_request_id(session: dict[str, Any], action: str, message: str, reply_to: Optional[str]) -> str:
    """Deterministic idempotency key for daemon /send-requests.

    Replies to the same daemon event must reuse the same key across Gateway
    restarts so liberdusd can dedupe accepted sends.  For explicit sends
    without a reply target, include only a message hash so the key never embeds
    plaintext.
    """
    message_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    target = str(reply_to or message_hash)
    seed = ":".join(
        [
            str(session.get("accountId") or ""),
            str(session.get("chatId") or ""),
            str(session.get("contactId") or ""),
            action,
            target,
        ]
    )
    return f"gw_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:32]}"


def _liberdus_channel_prompt(profile: str, policy_mode: str) -> str:
    if profile == "dbp" and policy_mode == "full":
        return (
            "Liberdus dev adapter policy: this message is from dbp, a trusted full-access "
            "counterparty. Normal Hermes tools may be used when otherwise authorized."
        )
    if profile == "test" and policy_mode == "restricted-chat-only":
        return (
            "Liberdus dev adapter policy: this message is from test, a restricted chat-only "
            "counterparty. Tool use is disabled for this turn; answer conversationally only."
        )
    return ""


def _safe_payload(value: Any) -> Any:
    """Return a JSON-safe copy with secret-bearing fields and sentinels removed."""
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_s = str(key)
            if _SECRET_KEY_RE.search(key_s):
                clean[key_s] = "[redacted]"
                continue
            clean[key_s] = _safe_payload(item)
        return clean
    if isinstance(value, list):
        return [_safe_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_payload(item) for item in value]
    if isinstance(value, str):
        return _scrub_text(value)
    return value


def _error_message(payload: Any, fallback: str) -> str:
    safe = _safe_payload(payload)
    if isinstance(safe, dict):
        err = safe.get("error")
        if isinstance(err, dict):
            code = str(err.get("code") or "").strip()
            message = str(err.get("message") or "").strip()
            if code and message:
                return f"{code}: {message}"
            if code:
                return code
            if message:
                return message
        message = safe.get("message") or safe.get("error")
        if isinstance(message, str) and message.strip():
            return message.strip()
    return _scrub_text(fallback)


def _daemon_error_code(payload: Any) -> str:
    safe = _safe_payload(payload)
    if isinstance(safe, dict):
        err = safe.get("error")
        if isinstance(err, dict):
            code = str(err.get("code") or "").strip()
            if code:
                return code
        if isinstance(err, str) and err.strip():
            return err.strip()
        code = safe.get("code")
        if isinstance(code, str) and code.strip():
            return code.strip()
    return "unknown"


def _log_value(value: Any, *, limit: int = 240) -> str:
    text = _scrub_text(str(value or "")).replace("\n", " ").replace("\r", " ").strip()
    if len(text) > limit:
        return text[:limit] + "…"
    return text


def _plaintext_log_summary(message: str) -> dict[str, Any]:
    scrubbed_preview = _log_value(message, limit=120)
    return {
        "bytes": len(message.encode("utf-8")),
        "sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
        "preview": scrubbed_preview,
    }


def _utf8_prefix_len(text: str, byte_limit: int) -> int:
    """Return a string index that fits inside byte_limit without splitting codepoints."""
    used = 0
    for index, char in enumerate(text):
        used += len(char.encode("utf-8"))
        if used > byte_limit:
            return index
    return len(text)


def _split_utf8_text(text: str, byte_limit: int) -> list[str]:
    """Split text into non-empty UTF-8 byte-bounded chunks."""
    if byte_limit <= 0:
        raise ValueError("byte_limit must be positive")
    remaining = text
    chunks: list[str] = []
    while remaining:
        if len(remaining.encode("utf-8")) <= byte_limit:
            chunks.append(remaining)
            break
        hard_end = _utf8_prefix_len(remaining, byte_limit)
        if hard_end <= 0:
            # Defensive fallback for pathological limits; callers use much larger limits.
            hard_end = 1
        split_at = hard_end
        soft_window = remaining[:hard_end]
        # Prefer natural boundaries near the end of the chunk, but do not create tiny fragments.
        for pattern in ("\n\n", "\n", ". ", "! ", "? ", " "):
            candidate = soft_window.rfind(pattern)
            if candidate >= max(1, hard_end // 2):
                split_at = candidate + len(pattern)
                break
        chunk = remaining[:split_at].rstrip()
        if not chunk:
            chunk = remaining[:hard_end]
            split_at = hard_end
        chunks.append(chunk)
        remaining = remaining[split_at:].lstrip()
    return chunks


def _split_liberdus_outbound_message(message: str, *, max_bytes: int = LIBERDUS_OUTBOUND_MESSAGE_MAX_BYTES) -> list[str]:
    """Return web-client-compatible outbound Liberdus chunks.

    liberdusd enforces the web-client-v2 plaintext limit before accepting
    /send-requests.  The Gateway must therefore split long replies before POSTing
    them.  Multi-part replies include a small ordering prefix that is counted
    against the same byte limit.
    """
    if len(message.encode("utf-8")) <= max_bytes:
        return [message]

    digit_count = 1
    for _ in range(8):
        worst_prefix = f"({str(9) * digit_count}/{str(9) * digit_count})\n"
        payload_limit = max_bytes - len(worst_prefix.encode("utf-8"))
        if payload_limit <= 0:
            raise ValueError("max_bytes too small for Liberdus chunk prefix")
        raw_chunks = _split_utf8_text(message, payload_limit)
        needed_digits = len(str(len(raw_chunks)))
        if needed_digits == digit_count:
            break
        digit_count = needed_digits
    else:
        raw_chunks = _split_utf8_text(message, max_bytes - 32)

    total = len(raw_chunks)
    chunks = [f"({index}/{total})\n{chunk}" for index, chunk in enumerate(raw_chunks, start=1)]
    if any(len(chunk.encode("utf-8")) > max_bytes for chunk in chunks):
        # Final defensive pass using the exact largest prefix for this total.
        worst_prefix = f"({total}/{total})\n"
        payload_limit = max_bytes - len(worst_prefix.encode("utf-8"))
        raw_chunks = _split_utf8_text(message, payload_limit)
        total = len(raw_chunks)
        chunks = [f"({index}/{total})\n{chunk}" for index, chunk in enumerate(raw_chunks, start=1)]
    return chunks


def _log_send_failure(
    *,
    status_code: Any,
    payload: Any,
    request: dict[str, Any],
    message: str,
    fallback: str,
    retryable: bool,
) -> None:
    plaintext = _plaintext_log_summary(message)
    client_context = request.get("clientContext") if isinstance(request.get("clientContext"), dict) else {}
    logger.warning(
        "Liberdus send request rejected: "
        "http_status=%s daemon_code=%s daemon_error=%s retryable=%s "
        "action=%s account_id=%s chat_id=%s contact_id=%s adapter_request_id=%s reply_to=%s "
        "plaintext_bytes=%s plaintext_sha256=%s plaintext_preview=%r",
        _log_value(status_code, limit=40),
        _log_value(_daemon_error_code(payload), limit=120),
        _log_value(_error_message(payload, fallback), limit=240),
        bool(retryable),
        _log_value(request.get("action"), limit=80),
        _log_value(request.get("accountId"), limit=120),
        _log_value(request.get("chatId"), limit=120),
        _log_value(request.get("contactId"), limit=120),
        _log_value(client_context.get("adapterRequestId"), limit=120),
        _log_value(client_context.get("replyToEventId"), limit=120),
        plaintext["bytes"],
        plaintext["sha256"],
        plaintext["preview"],
    )


def check_liberdus_requirements() -> bool:
    """Liberdus uses the bundled httpx dependency and a user-started daemon."""
    return True


def liberdus_env_config() -> Optional[dict[str, Any]]:
    """Parse LIBERDUS_* env vars for GatewayConfig env override wiring.

    Fail closed: when enabled, exactly one local daemon endpoint and the dev
    network profile are required. Invalid combinations return None so the
    platform is not auto-enabled.
    """
    if not _bool_env(os.getenv("LIBERDUS_ENABLED")):
        return None

    api_url = _configured_http_url()
    api_socket = (os.getenv("LIBERDUS_API_SOCKET") or "").strip() or None
    network_profile = (os.getenv("LIBERDUS_NETWORK_PROFILE") or "dev").strip().lower()
    if network_profile != "dev":
        return None
    if api_url == "__conflicting_liberdus_http_url__":
        return None
    if bool(api_url) == bool(api_socket):
        return None
    if api_url and not _is_loopback_url(api_url):
        return None
    if api_socket and not api_socket.startswith("/"):
        return None
    api_token = (os.getenv("LIBERDUS_API_TOKEN") or os.getenv("LIBERDUS_DAEMON_API_TOKEN") or "").strip()
    if not api_token:
        return None

    account_labels = _split_allowlist(os.getenv("LIBERDUS_ACCOUNT_LABELS"))
    counterparty_profiles = _configured_counterparty_profiles()
    if counterparty_profiles == [] and os.getenv("LIBERDUS_COUNTERPARTY_PROFILES"):
        return None

    poll_interval_ms = _coerce_int(
        os.getenv("LIBERDUS_POLL_INTERVAL_MS"),
        DEFAULT_POLL_INTERVAL_MS,
        minimum=MIN_POLL_INTERVAL_MS,
    )
    events_page_size = _coerce_int(
        os.getenv("LIBERDUS_EVENTS_PAGE_SIZE"),
        DEFAULT_EVENTS_PAGE_SIZE,
        minimum=1,
        maximum=MAX_EVENTS_PAGE_SIZE,
    )
    result = {
        "api_url": api_url,
        "api_socket": api_socket,
        "network_profile": network_profile,
        "api_token": api_token,
        "poll_interval_ms": poll_interval_ms,
        "events_page_size": events_page_size,
    }
    if account_labels:
        result["account_labels"] = account_labels
    if counterparty_profiles:
        result["counterparty_profiles"] = counterparty_profiles
    return result


class LiberdusAdapter(BasePlatformAdapter):
    """Hermes Gateway adapter for a local liberdusd daemon."""

    platform = Platform.LIBERDUS
    SUPPORTS_MESSAGE_EDITING = False

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.LIBERDUS)
        extra = config.extra or {}
        self.api_url = str(extra.get("api_url") or "").strip().rstrip("/") or None
        self.api_socket = str(extra.get("api_socket") or "").strip() or None
        self.api_token = str(extra.get("api_token") or "").strip() or None
        self.network_profile = str(extra.get("network_profile") or "dev").strip().lower()
        self.poll_interval_ms = _coerce_int(
            extra.get("poll_interval_ms"),
            DEFAULT_POLL_INTERVAL_MS,
            minimum=MIN_POLL_INTERVAL_MS,
        )
        self.events_page_size = _coerce_int(
            extra.get("events_page_size"),
            DEFAULT_EVENTS_PAGE_SIZE,
            minimum=1,
            maximum=MAX_EVENTS_PAGE_SIZE,
        )
        self.account_labels = _allowlist_set(extra.get("account_labels"))
        self.counterparty_profiles = _allowlist_set(extra.get("counterparty_profiles")) or set(_ALLOWED_PROFILES)
        self.client: Any = None
        self._poll_task: asyncio.Task | None = None
        self._accounts: list[dict[str, Any]] = []
        self._cursor_by_account: dict[str, str | None] = {}
        self._seen_event_ids: set[str] = set()
        self._sessions: dict[str, dict[str, Any]] = {}

    async def connect(self) -> bool:
        if not self._validate_endpoint_config():
            return False
        try:
            self.client = self._make_client()
            health = await self._get_json("/health")
            status = await self._get_json("/status")
            self._validate_daemon_status(health, status)
            accounts_payload = await self._get_json("/accounts")
            accounts = accounts_payload.get("accounts") if isinstance(accounts_payload, dict) else None
            self._accounts = [a for a in (accounts or []) if isinstance(a, dict) and self._account_allowed(a)]
            daemon_cursors = status.get("adapterCursors") if isinstance(status.get("adapterCursors"), dict) else {}
            self._cursor_by_account = {}
            for account in self._accounts:
                account_id = str(account.get("accountId") or account.get("id") or "")
                if not account_id:
                    continue
                cursor_record = daemon_cursors.get(account_id) if isinstance(daemon_cursors, dict) else None
                cursor = cursor_record.get("cursor") if isinstance(cursor_record, dict) else None
                self._cursor_by_account[account_id] = str(cursor) if cursor else None
            # If the daemon has no accounts yet, keep one global poll cursor so
            # tests and future daemon implementations that do not require
            # accountId still work without synthesizing account identity.
            if not self._cursor_by_account:
                self._cursor_by_account[""] = None
            self._mark_connected()
            self._poll_task = asyncio.create_task(self._poll_loop())
            logger.info("Liberdus adapter connected to local liberdusd endpoint")
            return True
        except Exception as exc:
            if self.client is not None:
                try:
                    await self.client.aclose()
                except Exception:
                    pass
                self.client = None
            message = f"liberdusd unavailable or unhealthy: {_scrub_text(str(exc))}"
            code = "daemon_unavailable" if isinstance(exc, (httpx.ConnectError, httpx.TransportError)) else "daemon_unhealthy"
            self._set_fatal_error(code, message, retryable=True)
            return False

    async def disconnect(self) -> None:
        self._mark_disconnected()
        if self._poll_task is not None:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        if self.client is not None:
            try:
                await self.client.aclose()
            finally:
                self.client = None

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        session = self._sessions.get(str(chat_id)) or {}
        display = session.get("counterpartyDisplay") or session.get("counterpartyProfile") or str(chat_id)
        account = session.get("accountLabel") or session.get("accountId") or "liberdus"
        return {
            "name": f"Liberdus / {display} / {account}",
            "type": "dm",
            "id": str(chat_id),
            "metadata": _safe_payload(session),
        }

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SendResult:
        if not self.client or not self.is_connected:
            return SendResult(success=False, error="liberdusd unavailable", retryable=True)
        message = content or ""
        if not message.strip():
            return SendResult(success=False, error="invalid_request: empty message")

        session = self._sessions.get(str(chat_id))
        if not session:
            return SendResult(success=False, error="chat_not_found: unknown or quarantined Liberdus chat")
        if session.get("policyMode") == "quarantine":
            return SendResult(success=False, error="quarantined_contact: outbound replies denied")

        action = session.get("replyAction")
        profile = session.get("counterpartyProfile")
        policy_mode = session.get("policyMode")
        if profile == "dbp" and action != "send-message":
            return SendResult(success=False, error="policy_denied: dbp requires send-message")
        if profile == "test" and action != "reply-test":
            return SendResult(success=False, error="restricted_action_denied: test requires reply-test")
        if action not in {"send-message", "reply-test"}:
            return SendResult(success=False, error="policy_denied: outbound action unavailable")

        chunks = _split_liberdus_outbound_message(message)
        original_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
        raw_responses: list[Any] = []
        handles: list[str] = []
        request: dict[str, Any] = {}

        try:
            for index, chunk in enumerate(chunks, start=1):
                request = {
                    "schemaVersion": 1,
                    "accountId": session.get("accountId"),
                    "chatId": session.get("chatId"),
                    "contactId": session.get("contactId"),
                    "counterpartyProfile": profile,
                    "action": action,
                    "message": chunk,
                    "clientContext": {
                        "platform": "liberdus",
                        "adapterRequestId": _stable_adapter_request_id(session, str(action), chunk, f"{reply_to}:chunk:{index}" if len(chunks) > 1 else reply_to),
                        "replyToEventId": reply_to,
                        "policyMode": policy_mode,
                    },
                }
                if len(chunks) > 1:
                    request["clientContext"]["chunk"] = {
                        "index": index,
                        "total": len(chunks),
                        "originalPlaintextSha256": original_hash,
                    }
                if metadata:
                    request["clientContext"]["metadata"] = _safe_payload(metadata)

                response = await self.client.post("/send-requests", json=request, headers=self._auth_headers())
                try:
                    payload = response.json()
                except Exception as exc:
                    payload = {"ok": False, "error": {"code": "invalid_daemon_response", "message": _scrub_text(str(exc))}}
                safe_response = _safe_payload(payload)
                raw_responses.append(safe_response)
                status_code = getattr(response, "status_code", 200)
                if status_code >= 400 or not payload.get("ok", True) or payload.get("accepted") is False:
                    fallback = f"liberdusd send rejected with HTTP {status_code}"
                    _log_send_failure(
                        status_code=status_code,
                        payload=payload,
                        request=request,
                        message=chunk,
                        fallback=fallback,
                        retryable=False,
                    )
                    return SendResult(
                        success=False,
                        error=_error_message(payload, fallback),
                        raw_response=safe_response,
                        retryable=False,
                    )
                acceptance = payload.get("gatewayAcceptance") if isinstance(payload, dict) else None
                handle = acceptance.get("handle") if isinstance(acceptance, dict) else None
                handle = str(handle or payload.get("messageId") or payload.get("txid") or "")
                if handle:
                    handles.append(handle)
            return SendResult(
                success=True,
                message_id=handles[-1] if handles else "",
                raw_response=raw_responses[-1] if len(raw_responses) == 1 else {"ok": True, "chunks": raw_responses},
            )
        except (httpx.ConnectError, httpx.TransportError) as exc:
            payload = {"ok": False, "error": {"code": "daemon_unavailable", "message": _scrub_text(str(exc))}}
            _log_send_failure(
                status_code="transport_error",
                payload=payload,
                request=request,
                message=message,
                fallback="liberdusd unavailable",
                retryable=True,
            )
            return SendResult(success=False, error=f"liberdusd unavailable: {_scrub_text(str(exc))}", retryable=True)
        except Exception as exc:
            payload = {"ok": False, "error": {"code": "send_failed", "message": _scrub_text(str(exc))}}
            _log_send_failure(
                status_code="exception",
                payload=payload,
                request=request,
                message=message,
                fallback="liberdusd send failed",
                retryable=False,
            )
            return SendResult(success=False, error=f"liberdusd send failed: {_scrub_text(str(exc))}", retryable=False)

    async def on_processing_start(self, event: MessageEvent) -> None:
        """Set a Liberdus processing reaction on the source message."""
        await self._send_processing_reaction(event, _PROCESSING_REACTION)

    async def on_processing_complete(self, event: MessageEvent, outcome: ProcessingOutcome) -> None:
        """Replace the processing reaction with a final success/failure marker."""
        if outcome == ProcessingOutcome.SUCCESS:
            emoji = _SUCCESS_REACTION
        elif outcome == ProcessingOutcome.CANCELLED:
            emoji = _CANCELLED_REACTION
        else:
            emoji = _FAILURE_REACTION
        await self._send_processing_reaction(event, emoji)

    async def _send_processing_reaction(self, event: MessageEvent, emoji: str) -> None:
        """Ask liberdusd to submit a web-client-v2-compatible reaction control message.

        Liberdus web-client-v2 models reactions as encrypted structured `message`
        tx payloads containing reactId/reactAction/reactMessage.  The adapter
        only sends redacted metadata to the local daemon; liberdusd owns signing,
        encryption, and devnet submission.  Failures are intentionally soft so a
        missing/older daemon reaction route cannot break normal message handling.
        """
        if not self.client or not self.is_connected:
            return
        session = self._sessions.get(str(event.source.chat_id))
        if not session or session.get("policyMode") == "quarantine":
            return
        react_id = str(session.get("lastReactionTarget") or event.message_id or "").strip()
        if not react_id:
            return
        request = {
            "schemaVersion": 1,
            "accountId": session.get("accountId"),
            "chatId": session.get("chatId"),
            "contactId": session.get("contactId"),
            "counterpartyProfile": session.get("counterpartyProfile"),
            "reactId": react_id,
            "reactAction": "set",
            "reactMessage": emoji,
            "clientContext": {
                "platform": "liberdus",
                "lifecycle": "processing",
                "replyToEventId": event.message_id,
                "policyMode": session.get("policyMode"),
            },
        }
        try:
            response = await self.client.post("/send-reactions", json=request, headers=self._auth_headers())
            if getattr(response, "status_code", 200) >= 400:
                logger.debug("Liberdus processing reaction rejected: %s", _error_message(response.json(), "reaction rejected"))
        except Exception as exc:
            logger.debug("Liberdus processing reaction failed: %s", _scrub_text(str(exc)))

    async def _poll_loop(self) -> None:
        while self.is_connected:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Liberdus poll failed: %s", _scrub_text(str(exc)))
            await asyncio.sleep(self.poll_interval_ms / 1000.0)

    async def _poll_once(self) -> None:
        if not self.client:
            return
        for account_id, cursor in list(self._cursor_by_account.items()):
            params: dict[str, Any] = {"limit": self.events_page_size}
            if account_id:
                params["accountId"] = account_id
            if cursor:
                params["after"] = cursor
            path = "/events?" + urlencode(params)
            payload = await self._get_json(path)
            events = payload.get("events") if isinstance(payload, dict) else None
            if not isinstance(events, list):
                continue
            last_delivered_event_id: str | None = None
            for raw_event in events:
                if not isinstance(raw_event, dict):
                    continue
                event_id = str(raw_event.get("eventId") or "").strip()
                if not event_id or event_id in self._seen_event_ids:
                    continue
                self._seen_event_ids.add(event_id)
                message_event = self._event_to_message(raw_event)
                if message_event is None:
                    continue
                response = None
                if self._message_handler is not None:
                    await self._run_processing_hook("on_processing_start", message_event)
                    processing_ok = False
                    try:
                        response = await self._message_handler(message_event)
                        if response:
                            send_result = await self.send(
                                message_event.source.chat_id,
                                str(response),
                                reply_to=message_event.message_id,
                            )
                            processing_ok = bool(send_result.success)
                        else:
                            processing_ok = True
                    except Exception:
                        await self._run_processing_hook(
                            "on_processing_complete",
                            message_event,
                            ProcessingOutcome.FAILURE,
                        )
                        raise
                    await self._run_processing_hook(
                        "on_processing_complete",
                        message_event,
                        ProcessingOutcome.SUCCESS if processing_ok else ProcessingOutcome.FAILURE,
                    )
                last_delivered_event_id = event_id
            if last_delivered_event_id:
                self._cursor_by_account[account_id] = last_delivered_event_id
                await self._ack_event(account_id, last_delivered_event_id)
            else:
                next_cursor = payload.get("nextCursor") if isinstance(payload, dict) else None
                if next_cursor and next_cursor == cursor:
                    self._cursor_by_account[account_id] = str(next_cursor)

    def _account_allowed(self, payload: dict[str, Any]) -> bool:
        if not self.account_labels:
            return True
        account_label = str(payload.get("accountLabel") or payload.get("label") or "").strip()
        account_id = str(payload.get("accountId") or payload.get("id") or "").strip()
        return account_label in self.account_labels or account_id in self.account_labels

    def _event_to_message(self, event: dict[str, Any]) -> MessageEvent | None:
        if event.get("network") and str(event.get("network")).lower() != "dev":
            return None
        if not self._account_allowed(event):
            return None
        if event.get("direction") != "inbound" or event.get("eventType") != "message.inbound":
            return None
        if str(event.get("visibility") or "normal") != "normal":
            return None
        profile = str(event.get("counterpartyProfile") or "").strip()
        policy_mode = str(event.get("policyMode") or "").strip()
        if profile not in _ALLOWED_PROFILES or profile not in self.counterparty_profiles or policy_mode not in _ALLOWED_POLICY_MODES:
            return None
        reply = event.get("reply") if isinstance(event.get("reply"), dict) else {}
        reply_action = str(reply.get("action") or "").strip()
        if profile == "dbp" and (policy_mode != "full" or reply_action != "send-message"):
            return None
        if profile == "test" and (policy_mode != "restricted-chat-only" or reply_action != "reply-test"):
            return None

        plaintext = event.get("plaintext") if isinstance(event.get("plaintext"), dict) else {}
        text = plaintext.get("preview")
        if not isinstance(text, str) or not text:
            return None

        account_id = str(event.get("accountId") or "").strip()
        raw_chat_id = str(event.get("chatId") or event.get("platformChatId") or "").strip()
        if not account_id or not raw_chat_id:
            return None
        hermes_chat_id = str(event.get("hermesChatId") or f"liberdus:dm:{account_id}:{raw_chat_id}")
        if not hermes_chat_id.startswith(f"liberdus:dm:{account_id}:"):
            return None

        account_label = str(event.get("accountLabel") or account_id)
        display = str(event.get("counterpartyDisplay") or profile)
        chat_name = f"Liberdus / {display} / {account_label}"
        contact_id = str(event.get("contactId") or profile)
        safe_event = _safe_payload(event)

        self._sessions[hermes_chat_id] = {
            "accountId": account_id,
            "accountLabel": account_label,
            "chatId": raw_chat_id,
            "platformChatId": str(event.get("platformChatId") or raw_chat_id),
            "contactId": contact_id,
            "counterpartyProfile": profile,
            "counterpartyDisplay": display,
            "capabilityClass": event.get("capabilityClass"),
            "policyMode": policy_mode,
            "replyAction": reply_action,
            "lastReactionTarget": str(event.get("txid") or event.get("appReceiptId") or event.get("messageId") or event.get("eventId") or ""),
        }

        return MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=SessionSource(
                platform=Platform.LIBERDUS,
                chat_id=hermes_chat_id,
                chat_name=chat_name,
                chat_type="dm",
                user_id=contact_id,
                user_name=display,
                chat_topic=policy_mode,
                message_id=str(event.get("eventId") or ""),
            ),
            raw_message=safe_event,
            message_id=str(event.get("eventId") or ""),
            channel_prompt=_liberdus_channel_prompt(profile, policy_mode),
            timestamp=_parse_timestamp(event.get("observedAt")),
        )

    def _auth_headers(self) -> dict[str, str]:
        if not self.api_token:
            return {}
        return {"Authorization": f"Bearer {self.api_token}"}

    async def _ack_event(self, account_id: str, cursor: str) -> None:
        if not account_id or not cursor:
            return
        try:
            await self.client.post(
                "/events/ack",
                json={"schemaVersion": 1, "accountId": account_id, "cursor": cursor},
                headers=self._auth_headers(),
            )
        except Exception as exc:
            logger.warning("Liberdus event ack failed: %s", _scrub_text(str(exc)))

    def _make_client(self) -> httpx.AsyncClient:
        if self.api_socket:
            transport = httpx.AsyncHTTPTransport(uds=self.api_socket)
            return httpx.AsyncClient(base_url="http://liberdusd", transport=transport, timeout=15.0)
        return httpx.AsyncClient(base_url=self.api_url, timeout=15.0)

    async def _get_json(self, path: str) -> dict[str, Any]:
        response = await self.client.get(path)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("liberdusd returned non-object JSON")
        return payload

    def _validate_endpoint_config(self) -> bool:
        if self.network_profile != "dev":
            self._set_fatal_error("unsupported_network", "liberdusd adapter only supports dev network", retryable=False)
            return False
        if bool(self.api_url) == bool(self.api_socket):
            self._set_fatal_error(
                "invalid_request",
                "liberdusd requires exactly one local API endpoint (api_url or api_socket)",
                retryable=False,
            )
            return False
        if not self.api_token:
            self._set_fatal_error("local_auth_required", "liberdusd API token is required for privileged ack/send routes", retryable=False)
            return False
        if self.api_url and not _is_loopback_url(self.api_url):
            self._set_fatal_error("invalid_request", "liberdusd API URL must be loopback-local", retryable=False)
            return False
        if self.api_socket and not self.api_socket.startswith("/"):
            self._set_fatal_error("invalid_request", "liberdusd API socket must be an absolute path", retryable=False)
            return False
        return True

    def _validate_daemon_status(self, health: dict[str, Any], status: dict[str, Any]) -> None:
        for label, payload in (("health", health), ("status", status)):
            if payload.get("service") != "liberdusd":
                raise RuntimeError(f"liberdusd {label} service mismatch")
            if payload.get("secretBoundary") != "redacted-api":
                raise RuntimeError(f"liberdusd {label} does not expose redacted-api boundary")
            network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
            if str(network.get("profile") or "").lower() != "dev":
                raise RuntimeError(f"liberdusd {label} is not on dev network")
            origin = network.get("gatewayOrigin")
            if origin and str(origin) not in _ALLOWED_DEV_ORIGINS:
                raise RuntimeError(f"liberdusd {label} gateway origin is not dev")
            inject = network.get("injectEndpoint")
            if inject and str(inject) != _EXACT_DEV_INJECT:
                raise RuntimeError(f"liberdusd {label} inject endpoint is not dev")
            binding = payload.get("binding") if isinstance(payload.get("binding"), dict) else {}
            if binding:
                kind = str(binding.get("kind") or "").lower()
                host = str(binding.get("host") or "").lower()
                local_only = binding.get("localOnly") is True
                if kind == "tcp" and (host not in _LOOPBACK_HOSTS or not local_only):
                    raise RuntimeError(f"liberdusd {label} binding is not loopback-local")
                if kind and kind not in {"tcp", "unix", "socket"}:
                    raise RuntimeError(f"liberdusd {label} binding kind is unsupported")
        readiness = status.get("readiness") if isinstance(status.get("readiness"), dict) else {}
        if readiness and readiness.get("canReadState") is False:
            raise RuntimeError("liberdusd cannot read state")


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)
