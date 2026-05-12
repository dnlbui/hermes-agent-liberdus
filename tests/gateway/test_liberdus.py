"""Tests for the Liberdus Gateway platform adapter.

These tests use a fake liberdusd/local API only.  They intentionally avoid the
live Liberdus dev network and use sentinel strings (not real secrets) to verify
that the adapter preserves the daemon secret boundary.
"""

import asyncio
import hashlib
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig, _apply_env_overrides


FORBIDDEN_SENTINELS = (
    "SENTINEL_PRIVATE_KEY",
    "SENTINEL_PQ_SEED",
    "SENTINEL_CIPHERTEXT",
    "SENTINEL_SIGNED_TX",
)


@dataclass
class _FakeResponse:
    status_code: int
    payload: dict[str, Any]

    def json(self) -> dict[str, Any]:
        return self.payload

    @property
    def text(self) -> str:
        return json.dumps(self.payload)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "http://127.0.0.1/fake"),
                response=httpx.Response(self.status_code, json=self.payload),
            )


class _FakeSseStream:
    def __init__(self, lines: list[str], *, status_code: int = 200) -> None:
        self.lines = lines
        self.status_code = status_code

    async def __aenter__(self) -> "_FakeSseStream":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "http://127.0.0.1/events/stream"),
                response=httpx.Response(self.status_code, json={"ok": False}),
            )

    async def aiter_lines(self):
        for line in self.lines:
            await asyncio.sleep(0)
            yield line


class _FakeLiberdusClient:
    def __init__(self, daemon: "_FakeLiberdusDaemon") -> None:
        self.daemon = daemon
        self.closed = False

    async def get(self, path: str, **_kwargs: Any) -> _FakeResponse:
        self.daemon.requests.append(("GET", path, None))
        if self.daemon.raise_on_get:
            raise httpx.ConnectError("liberdusd unavailable")
        if path == "/health":
            return _FakeResponse(200, self.daemon.health)
        if path == "/status":
            return _FakeResponse(200, self.daemon.status)
        if path == "/accounts":
            return _FakeResponse(200, {"accounts": self.daemon.accounts})
        if path.startswith("/events"):
            return _FakeResponse(200, self.daemon.events_response(path))
        return _FakeResponse(404, {"ok": False, "error": {"code": "not_found"}})

    def stream(self, method: str, path: str, **_kwargs: Any) -> _FakeSseStream:
        self.daemon.requests.append(("STREAM", f"{method} {path}", None))
        if self.daemon.raise_on_stream:
            raise httpx.ConnectError("liberdusd event stream unavailable")
        return _FakeSseStream(self.daemon.stream_lines, status_code=self.daemon.stream_status_code)

    async def post(self, path: str, json: dict[str, Any] | None = None, **_kwargs: Any) -> _FakeResponse:
        self.daemon.requests.append(("POST", path, json))
        if self.daemon.raise_on_post:
            raise httpx.ConnectError("liberdusd unavailable")
        if path == "/events/ack":
            self.daemon.acks.append(dict(json or {}))
            return _FakeResponse(200, {"ok": True, "cursor": (json or {}).get("cursor")})
        if path == "/send-reactions":
            self.daemon.reaction_requests.append(dict(json or {}))
            return _FakeResponse(200, {"ok": True, "accepted": True, "state": "accepted"})
        if path != "/send-requests":
            return _FakeResponse(404, {"ok": False, "error": {"code": "not_found"}})
        self.daemon.send_requests.append(dict(json or {}))
        if self.daemon.send_failure:
            return _FakeResponse(self.daemon.send_failure_status, self.daemon.send_failure)
        return _FakeResponse(
            200,
            {
                "ok": True,
                "accepted": True,
                "state": "accepted",
                "accountId": (json or {}).get("accountId"),
                "chatId": (json or {}).get("chatId"),
                "contactId": (json or {}).get("contactId"),
                "counterpartyProfile": (json or {}).get("counterpartyProfile"),
                "action": (json or {}).get("action"),
                "gatewayAcceptance": {"handle": "safe-dev-handle-123"},
                "devOnly": True,
            },
        )

    async def aclose(self) -> None:
        self.closed = True


class _FakeLiberdusDaemon:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []
        self.send_requests: list[dict[str, Any]] = []
        self.reaction_requests: list[dict[str, Any]] = []
        self.acks: list[dict[str, Any]] = []
        self.raise_on_get = False
        self.raise_on_post = False
        self.raise_on_stream = False
        self.stream_status_code = 200
        self.stream_lines: list[str] = []
        self.send_failure: dict[str, Any] | None = None
        self.send_failure_status = 502
        self.health = {
            "ok": True,
            "service": "liberdusd",
            "network": {"profile": "dev", "gatewayOrigin": "https://dev.liberdus.com:3030"},
            "binding": {"kind": "tcp", "host": "127.0.0.1", "localOnly": True},
            "secretBoundary": "redacted-api",
        }
        self.status = {
            "ok": True,
            "service": "liberdusd",
            "adapterContractVersion": 1,
            "readiness": {"state": "ready", "canReadState": True, "canSignOrSend": True},
            "network": {"profile": "dev", "gatewayOrigin": "https://dev.liberdus.com:3030"},
            "binding": {"kind": "tcp", "host": "127.0.0.1", "localOnly": True},
            "adapterCursors": {},
            "secretBoundary": "redacted-api",
        }
        self.accounts = [{"accountId": "acct-general", "label": "general", "network": "dev"}]
        self.events: list[dict[str, Any]] = []

    def client(self, *_args: Any, **_kwargs: Any) -> _FakeLiberdusClient:
        return _FakeLiberdusClient(self)

    def events_response(self, path: str) -> dict[str, Any]:
        after = None
        if "after=" in path:
            after = path.split("after=", 1)[1].split("&", 1)[0] or None
        start = 0
        if after:
            event_ids = [event["eventId"] for event in self.events]
            if after in event_ids:
                start = event_ids.index(after) + 1
        visible_events = self.events[start:]
        next_cursor = visible_events[-1]["eventId"] if visible_events else after
        return {"events": visible_events, "nextCursor": next_cursor}


def _adapter_config(**extra: Any) -> PlatformConfig:
    config = PlatformConfig(enabled=True)
    config.extra = {
        "api_url": "http://127.0.0.1:9484",
        "api_token": "test-local-token",
        "network_profile": "dev",
        "poll_interval_ms": 2000,
        "events_page_size": 50,
        **extra,
    }
    return config


def _make_event(
    event_id: str,
    profile: str,
    *,
    chat_id: str | None = None,
    preview: str = "hello from liberdus",
    policy_mode: str | None = None,
    reply_action: str | None = None,
    reply_allowed: bool | None = None,
    visibility: str = "normal",
    account_id: str = "acct-general",
    account_label: str = "general",
) -> dict[str, Any]:
    chat_id = chat_id or f"chat-{profile}"
    policy_mode = policy_mode or "allowed"
    reply_action = reply_action or "send-message"
    if reply_allowed is None:
        reply_allowed = visibility == "normal" and reply_action == "send-message"
    return {
        "schemaVersion": 1,
        "eventId": event_id,
        "accountId": account_id,
        "accountLabel": account_label,
        "chatId": chat_id,
        "platformChatId": chat_id,
        "hermesChatId": f"liberdus:dm:{account_id}:{chat_id}",
        "contactId": f"contact-{profile}",
        "counterpartyProfile": profile,
        "counterpartyDisplay": profile,
        "capabilityClass": "allowed",
        "policyMode": policy_mode,
        "network": "dev",
        "direction": "inbound",
        "eventType": "message.inbound",
        "txType": "chat-message",
        "txid": f"tx-{event_id}",
        "senderAddress": f"{profile}-address-preview",
        "recipientAddress": "hermes-address-preview",
        "visibility": visibility,
        "observedTs": 1710000000000,
        "observedAt": "2026-05-10T00:00:00.000Z",
        "plaintext": {
            "policy": "preview-only",
            "available": True,
            "outputMode": "preview-only",
            "preview": preview,
            "bytes": len(preview.encode("utf-8")),
            "sha256": f"sha256-{event_id}",
            "lastDecryptedAt": "2026-05-10T00:00:00.000Z",
        },
        "reply": {"allowed": reply_allowed, "action": reply_action},
        "rawRefs": {"contentRedacted": True},
        # These sentinel values model a daemon/API regression.  The adapter must
        # not pass them into MessageEvent.text, source fields, errors, or logs.
        "payloadJson": {"privateKey": "SENTINEL_PRIVATE_KEY"},
        "rawTxJson": {"signedTx": "SENTINEL_SIGNED_TX"},
    }


def _assert_no_forbidden_sentinels(value: Any) -> None:
    encoded = json.dumps(value, default=str)
    for sentinel in FORBIDDEN_SENTINELS:
        assert sentinel not in encoded


def _sse_lines(*events: dict[str, Any]) -> list[str]:
    lines = [": liberdusd event stream ready", ""]
    for event in events:
        lines.extend([f"id: {event['eventId']}", "event: liberdus.event", f"data: {json.dumps(event)}", ""])
    return lines


async def _wait_for(predicate, *, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("timed out waiting for condition")
        await asyncio.sleep(0.01)


def _patch_http_client(monkeypatch: pytest.MonkeyPatch, daemon: _FakeLiberdusDaemon) -> None:
    import gateway.platforms.liberdus as liberdus

    monkeypatch.setattr(liberdus.httpx, "AsyncClient", daemon.client)


@pytest.mark.asyncio
async def test_fake_daemon_allowed_event_mapping_dedupe_and_resume(monkeypatch):
    """Any daemon-normalized allowed sender becomes a Liberdus session; denied events are ignored."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [
        _make_event("evt-dbp-1", "dbp", preview="dbp ping"),
        _make_event("evt-alice-1", "alice", preview="alice ping"),
        _make_event(
            "evt-unknown-1",
            "unknown",
            chat_id="chat-unknown",
            preview="should stay quarantined",
            policy_mode="quarantine",
            reply_action="none",
            reply_allowed=False,
            visibility="quarantine",
        ),
        _make_event(
            "evt-reply-disabled",
            "bob",
            preview="normal visibility but daemon denied reply",
            reply_action="none",
            reply_allowed=False,
        ),
        _make_event("evt-dbp-1", "dbp", preview="duplicate should not emit twice"),
    ]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    assert [event.message_id for event in delivered] == ["evt-dbp-1", "evt-alice-1"]
    dbp_event, alice_event = delivered
    assert dbp_event.text == "dbp ping"
    assert alice_event.text == "alice ping"
    assert dbp_event.source.platform.value == "liberdus"
    assert alice_event.source.platform.value == "liberdus"
    assert dbp_event.source.chat_id == "liberdus:dm:acct-general:chat-dbp"
    assert alice_event.source.chat_id == "liberdus:dm:acct-general:chat-alice"
    assert dbp_event.source.chat_name == "Liberdus / dbp / general"
    assert alice_event.source.chat_name == "Liberdus / alice / general"
    assert dbp_event.source.user_name == "dbp"
    assert alice_event.source.user_name == "alice"
    assert dbp_event.raw_message["policyMode"] == "allowed"
    assert alice_event.raw_message["policyMode"] == "allowed"
    assert dbp_event.raw_message["reply"]["action"] == "send-message"
    assert alice_event.raw_message["reply"]["action"] == "send-message"
    assert dbp_event.channel_prompt == ""
    assert alice_event.channel_prompt == ""
    assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-alice-1"}]
    _assert_no_forbidden_sentinels([dbp_event, alice_event])

    daemon.events.append(_make_event("evt-dbp-2", "dbp", preview="dbp resumed"))
    await adapter._poll_once()
    assert [event.message_id for event in delivered] == ["evt-dbp-1", "evt-alice-1", "evt-dbp-2"]
    assert delivered[-1].source.chat_id == dbp_event.source.chat_id


@pytest.mark.asyncio
async def test_adapter_uses_daemon_event_stream_before_polling(monkeypatch):
    """When liberdusd advertises SSE, Gateway handles streamed events without waiting for the local poll interval."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.status["eventStream"] = {"supported": True, "path": "/events/stream", "mode": "sse"}
    daemon.stream_lines = _sse_lines(_make_event("evt-stream-dbp", "dbp", preview="stream delivered"))
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config(poll_interval_ms=5000))
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    try:
        await _wait_for(lambda: len(delivered) == 1)
        assert delivered[0].message_id == "evt-stream-dbp"
        assert delivered[0].text == "stream delivered"
        assert any(request[0] == "STREAM" and "/events/stream" in request[1] for request in daemon.requests)
        assert not any(request[0] == "GET" and request[1].startswith("/events?") for request in daemon.requests)
        assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-stream-dbp"}]
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_adapter_falls_back_to_polling_when_event_stream_unavailable(monkeypatch, caplog):
    """A broken local SSE stream is not fatal; the adapter logs fallback and resumes existing polling."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.status["eventStream"] = {"supported": True, "path": "/events/stream", "mode": "sse"}
    daemon.raise_on_stream = True
    daemon.events = [_make_event("evt-polled-after-stream-failure", "dbp", preview="fallback delivered")]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config(poll_interval_ms=20))
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    caplog.set_level("INFO")
    assert await adapter.connect() is True
    try:
        await _wait_for(lambda: len(delivered) == 1)
        assert delivered[0].message_id == "evt-polled-after-stream-failure"
        assert any(request[0] == "STREAM" and "/events/stream" in request[1] for request in daemon.requests)
        assert any(request[0] == "GET" and request[1].startswith("/events?") for request in daemon.requests)
        assert "falling back to polling" in caplog.text
    finally:
        await adapter.disconnect()


def test_liberdus_sessions_keep_configured_tools_without_sender_tier_gating():
    from gateway.run import _apply_liberdus_session_tool_boundary
    from gateway.session import SessionSource

    trusted = SessionSource(
        platform=Platform.LIBERDUS,
        chat_id="liberdus:dm:acct:chat-hermesbot",
        user_name="HermesBot",
        chat_topic="allowed",
    )
    formerly_restricted = SessionSource(
        platform=Platform.LIBERDUS,
        chat_id="liberdus:dm:acct:chat-test",
        user_name="test",
        chat_topic="restricted-chat-only",
    )
    toolsets = ["file", "kanban", "terminal"]

    assert _apply_liberdus_session_tool_boundary(trusted, toolsets) == toolsets
    assert _apply_liberdus_session_tool_boundary(formerly_restricted, toolsets) == toolsets


@pytest.mark.asyncio
async def test_configured_account_allowlist_gates_events_without_sender_tiers(monkeypatch):
    """Gateway may narrow daemon-owned accounts, but sender allow/deny stays in liberdusd."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.accounts = [
        {"accountId": "acct-general", "label": "general", "network": "dev"},
        {"accountId": "acct-work", "label": "work", "network": "dev"},
    ]
    daemon.events = [
        _make_event("evt-dbp-allowed", "dbp", preview="dbp allowed"),
        _make_event("evt-test-filtered", "test", preview="test filtered"),
        _make_event(
            "evt-work-filtered",
            "dbp",
            chat_id="chat-work",
            preview="work account filtered",
            account_id="acct-work",
            account_label="work",
        ),
    ]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(
        _adapter_config(
            account_labels=["general"],
        )
    )
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    assert [event.message_id for event in delivered] == ["evt-dbp-allowed", "evt-test-filtered"]
    assert list(adapter._cursor_by_account.keys()) == ["acct-general"]
    assert delivered[0].source.chat_id == "liberdus:dm:acct-general:chat-dbp"
    assert delivered[1].source.chat_id == "liberdus:dm:acct-general:chat-test"
    assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-test-filtered"}]


@pytest.mark.asyncio
async def test_cursor_initializes_from_daemon_status_and_acks_after_delivery(monkeypatch):
    """Restarted adapters resume from daemon-owned cursors and ACK new cursors only after delivery."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.status["adapterCursors"] = {"acct-general": {"cursor": "evt-dbp-1"}}
    daemon.events = [
        _make_event("evt-dbp-1", "dbp", preview="already acknowledged"),
        _make_event("evt-test-1", "test", preview="new after restart"),
    ]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    assert [event.message_id for event in delivered] == ["evt-test-1"]
    assert any(request[0] == "GET" and "/events?" in request[1] and "after=evt-dbp-1" in request[1] for request in daemon.requests)
    assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-test-1"}]


@pytest.mark.asyncio
async def test_fake_daemon_outbound_uses_simple_send_message_action(monkeypatch):
    """Replies route through /send-requests with the daemon-owned allowed send action."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [
        _make_event("evt-dbp-1", "dbp", preview="dbp ping"),
        _make_event("evt-test-1", "test", preview="test ping"),
    ]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())

    async def handler(_event):
        return None

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    dbp_result = await adapter.send("liberdus:dm:acct-general:chat-dbp", "hello dbp", reply_to="evt-dbp-1")
    test_result = await adapter.send("liberdus:dm:acct-general:chat-test", "hello test", reply_to="evt-test-1")
    duplicate_dbp_result = await adapter.send("liberdus:dm:acct-general:chat-dbp", "hello dbp", reply_to="evt-dbp-1")

    assert dbp_result.success is True
    assert test_result.success is True
    assert duplicate_dbp_result.success is True
    assert dbp_result.message_id == "safe-dev-handle-123"
    assert test_result.message_id == "safe-dev-handle-123"
    assert [request["action"] for request in daemon.send_requests] == ["send-message", "send-message", "send-message"]
    assert daemon.send_requests[0]["schemaVersion"] == 1
    assert daemon.send_requests[0]["accountId"] == "acct-general"
    assert daemon.send_requests[0]["chatId"] == "chat-dbp"
    assert daemon.send_requests[0]["contactId"] == "contact-dbp"
    assert daemon.send_requests[0]["counterpartyProfile"] == "dbp"
    assert daemon.send_requests[0]["action"] == "send-message"
    assert daemon.send_requests[0]["message"] == "hello dbp"
    assert daemon.send_requests[0]["clientContext"]["platform"] == "liberdus"
    assert daemon.send_requests[0]["clientContext"]["replyToEventId"] == "evt-dbp-1"
    assert daemon.send_requests[0]["clientContext"]["policyMode"] == "allowed"
    assert daemon.send_requests[0]["clientContext"].get("adapterRequestId")
    assert (
        daemon.send_requests[2]["clientContext"]["adapterRequestId"]
        == daemon.send_requests[0]["clientContext"]["adapterRequestId"]
    )
    assert daemon.send_requests[1]["accountId"] == "acct-general"
    assert daemon.send_requests[1]["chatId"] == "chat-test"
    assert daemon.send_requests[1]["contactId"] == "contact-test"
    assert daemon.send_requests[1]["counterpartyProfile"] == "test"
    assert daemon.send_requests[1]["clientContext"]["policyMode"] == "allowed"
    _assert_no_forbidden_sentinels(daemon.send_requests)


@pytest.mark.asyncio
async def test_processing_lifecycle_sends_liberdus_reaction_controls(monkeypatch):
    """Lifecycle hooks post web-client-v2-shaped reaction controls to liberdusd."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [_make_event("evt-dbp-1", "dbp", preview="dbp ping")]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())
    delivered = []

    async def handler(event):
        delivered.append(event)
        return None

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()
    assert len(delivered) == 1

    assert [request["reactMessage"] for request in daemon.reaction_requests] == ["👀", "✅"]
    assert [request["reactAction"] for request in daemon.reaction_requests] == ["set", "set"]
    assert all(request["reactId"] == "tx-evt-dbp-1" for request in daemon.reaction_requests)
    assert daemon.reaction_requests[0]["schemaVersion"] == 1
    assert daemon.reaction_requests[0]["accountId"] == "acct-general"
    assert daemon.reaction_requests[0]["chatId"] == "chat-dbp"
    assert daemon.reaction_requests[0]["contactId"] == "contact-dbp"
    assert daemon.reaction_requests[0]["counterpartyProfile"] == "dbp"
    assert daemon.reaction_requests[0]["clientContext"]["platform"] == "liberdus"
    assert daemon.reaction_requests[0]["clientContext"]["lifecycle"] == "processing"
    assert daemon.reaction_requests[0]["clientContext"]["replyToEventId"] == "evt-dbp-1"
    _assert_no_forbidden_sentinels(daemon.reaction_requests)


@pytest.mark.asyncio
async def test_fake_daemon_send_failure_is_reported_without_secret_leakage(monkeypatch):
    """Daemon send failures become safe SendResult errors with secret-like fields scrubbed."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [_make_event("evt-dbp-1", "dbp", preview="dbp ping")]
    daemon.send_failure = {
        "ok": False,
        "accepted": False,
        "error": {
            "code": "gateway_rejected",
            "message": "inject rejected for SENTINEL_PRIVATE_KEY raw_tx_json={\"signedTx\":\"LEAK_FREEFORM_RAW_TX\"} payload_json={\"ciphertext\":\"LEAK_FREEFORM_PAYLOAD\"}",
        },
        "rawTxJson": {"signedTx": "SENTINEL_SIGNED_TX"},
        "payloadJson": {"ciphertext": "SENTINEL_CIPHERTEXT"},
    }
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())

    async def handler(_event):
        return None

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    result = await adapter.send("liberdus:dm:acct-general:chat-dbp", "hello", reply_to="evt-dbp-1")

    assert result.success is False
    assert "gateway_rejected" in (result.error or "")
    assert "LEAK_FREEFORM_RAW_TX" not in (result.error or "")
    assert "LEAK_FREEFORM_PAYLOAD" not in (result.error or "")
    _assert_no_forbidden_sentinels({"error": result.error, "raw_response": result.raw_response})


@pytest.mark.asyncio
async def test_rejected_outbound_send_logs_safe_diagnostics(monkeypatch, caplog):
    """Oversized daemon rejections are logged with identifiers and hashes, never full plaintext."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [_make_event("evt-dbp-1", "dbp", preview="dbp ping")]
    daemon.send_failure_status = 413
    daemon.send_failure = {
        "ok": False,
        "accepted": False,
        "error": {"code": "message_too_large", "message": "message exceeds 4096 bytes"},
    }
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())

    async def handler(_event):
        return None

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    rejected_message = "safe diagnostic preview " + ("x" * 500) + " SENTINEL_PRIVATE_KEY raw_tx_json={\"signedTx\":\"LEAK_RAW_TX\"}"
    with caplog.at_level("WARNING", logger="gateway.platforms.liberdus"):
        result = await adapter.send("liberdus:dm:acct-general:chat-dbp", rejected_message, reply_to="evt-dbp-1")

    assert result.success is False
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "Liberdus send request rejected" in log_text
    assert "http_status=413" in log_text
    assert "daemon_code=message_too_large" in log_text
    assert "plaintext_bytes=" in log_text
    assert f"plaintext_sha256={hashlib.sha256(rejected_message.encode('utf-8')).hexdigest()}" in log_text
    assert "action=send-message" in log_text
    assert "account_id=acct-general" in log_text
    assert "chat_id=chat-dbp" in log_text
    assert "contact_id=contact-dbp" in log_text
    assert "safe diagnostic preview" in log_text
    assert "SENTINEL_PRIVATE_KEY" not in log_text
    assert "LEAK_RAW_TX" not in log_text
    assert "x" * 500 not in log_text
    _assert_no_forbidden_sentinels({"error": result.error, "raw_response": result.raw_response, "logs": log_text})


@pytest.mark.asyncio
async def test_long_outbound_replies_are_chunked_before_send_requests(monkeypatch):
    """Liberdus replies over the web-client plaintext limit are split before POSTing."""
    from gateway.platforms.liberdus import LIBERDUS_OUTBOUND_MESSAGE_MAX_BYTES, LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [_make_event("evt-dbp-1", "dbp", preview="dbp ping")]
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())

    async def handler(_event):
        return None

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    long_message = "Intro line. " + ("chunk me please " * 120) + "✅ done"
    result = await adapter.send("liberdus:dm:acct-general:chat-dbp", long_message, reply_to="evt-dbp-1")

    assert result.success is True
    send_requests = daemon.send_requests
    assert len(send_requests) >= 2
    assert all(len(request["message"].encode("utf-8")) <= LIBERDUS_OUTBOUND_MESSAGE_MAX_BYTES for request in send_requests)
    assert [request["clientContext"]["chunk"]["index"] for request in send_requests] == list(range(1, len(send_requests) + 1))
    assert {request["clientContext"]["chunk"]["total"] for request in send_requests} == {len(send_requests)}
    assert {request["clientContext"]["chunk"]["originalPlaintextSha256"] for request in send_requests} == {
        hashlib.sha256(long_message.encode("utf-8")).hexdigest()
    }
    assert len({request["clientContext"]["adapterRequestId"] for request in send_requests}) == len(send_requests)
    assert send_requests[0]["message"].startswith(f"(1/{len(send_requests)})\n")
    assert send_requests[-1]["message"].startswith(f"({len(send_requests)}/{len(send_requests)})\n")
    reconstructed = " ".join(request["message"].split("\n", 1)[1].strip() for request in send_requests)
    assert "Intro line." in reconstructed
    assert "✅ done" in reconstructed
    assert result.raw_response["ok"] is True
    assert len(result.raw_response["chunks"]) == len(send_requests)
    _assert_no_forbidden_sentinels(send_requests)


@pytest.mark.asyncio
async def test_missing_daemon_reports_disconnected_status(monkeypatch):
    """A missing local daemon fails closed and leaves the platform disconnected."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.raise_on_get = True
    _patch_http_client(monkeypatch, daemon)

    adapter = LiberdusAdapter(_adapter_config())

    assert await adapter.connect() is False
    assert adapter.is_connected is False
    assert adapter.fatal_error_code in {"daemon_unhealthy", "daemon_unavailable"}
    assert "liberdusd" in (adapter.fatal_error_message or "")
    _assert_no_forbidden_sentinels(adapter.fatal_error_message)


def test_env_overrides_enable_liberdus_only_with_local_api_and_dev_profile(monkeypatch):
    monkeypatch.setenv("LIBERDUS_ENABLED", "true")
    monkeypatch.setenv("LIBERDUS_API_URL", "http://127.0.0.1:9484")
    monkeypatch.delenv("LIBERDUS_API_SOCKET", raising=False)
    monkeypatch.setenv("LIBERDUS_NETWORK_PROFILE", "dev")
    monkeypatch.setenv("LIBERDUS_API_TOKEN", "test-local-token")
    monkeypatch.setenv("LIBERDUS_POLL_INTERVAL_MS", "500")

    config = GatewayConfig()
    _apply_env_overrides(config)

    platform = Platform("liberdus")
    assert platform in config.platforms
    liberdus_config = config.platforms[platform]
    assert liberdus_config.enabled is True
    assert liberdus_config.extra["api_url"] == "http://127.0.0.1:9484"
    assert liberdus_config.extra["api_socket"] is None
    assert liberdus_config.extra["network_profile"] == "dev"
    assert liberdus_config.extra["api_token"] == "test-local-token"
    assert liberdus_config.extra["poll_interval_ms"] == 500


def test_env_overrides_accept_http_url_alias_and_account_labels(monkeypatch):
    """Final env contract supports LIBERDUS_HTTP_URL while sender allowlists stay daemon-owned."""
    monkeypatch.setenv("LIBERDUS_ENABLED", "true")
    monkeypatch.delenv("LIBERDUS_API_URL", raising=False)
    monkeypatch.setenv("LIBERDUS_HTTP_URL", "http://localhost:9484")
    monkeypatch.delenv("LIBERDUS_API_SOCKET", raising=False)
    monkeypatch.setenv("LIBERDUS_NETWORK_PROFILE", "dev")
    monkeypatch.setenv("LIBERDUS_DAEMON_API_TOKEN", "daemon-local-token")
    monkeypatch.setenv("LIBERDUS_ACCOUNT_LABELS", "general, work")
    monkeypatch.setenv("LIBERDUS_ALLOWED_SENDERS", "dbp")
    monkeypatch.setenv("LIBERDUS_COUNTERPARTY_PROFILES", "test")

    config = GatewayConfig()
    _apply_env_overrides(config)

    liberdus_config = config.platforms[Platform("liberdus")]
    assert liberdus_config.extra["api_url"] == "http://localhost:9484"
    assert liberdus_config.extra["account_labels"] == ["general", "work"]
    assert "counterparty_profiles" not in liberdus_config.extra
    assert "allowed_senders" not in liberdus_config.extra
    assert liberdus_config.extra["api_token"] == "daemon-local-token"


def test_env_overrides_reject_missing_or_conflicting_daemon_endpoint(monkeypatch):
    monkeypatch.setenv("LIBERDUS_ENABLED", "true")
    monkeypatch.setenv("LIBERDUS_NETWORK_PROFILE", "dev")
    monkeypatch.delenv("LIBERDUS_API_URL", raising=False)
    monkeypatch.delenv("LIBERDUS_HTTP_URL", raising=False)
    monkeypatch.delenv("LIBERDUS_API_SOCKET", raising=False)

    config = GatewayConfig()
    _apply_env_overrides(config)
    assert Platform("liberdus") not in config.platforms

    monkeypatch.setenv("LIBERDUS_API_URL", "http://127.0.0.1:9484")
    monkeypatch.setenv("LIBERDUS_API_SOCKET", "/tmp/liberdusd.sock")
    config = GatewayConfig()
    _apply_env_overrides(config)
    assert Platform("liberdus") not in config.platforms


def test_connected_platforms_require_exactly_one_local_dev_endpoint():
    platform = Platform("liberdus")

    local_http = GatewayConfig(platforms={platform: _adapter_config(api_socket=None)})
    assert platform in local_http.get_connected_platforms()

    local_socket = GatewayConfig(platforms={platform: _adapter_config(api_url=None, api_socket="/tmp/liberdusd.sock")})
    assert platform in local_socket.get_connected_platforms()

    remote_http = GatewayConfig(platforms={platform: _adapter_config(api_url="https://liberdus.com/dev", api_socket=None)})
    assert platform not in remote_http.get_connected_platforms()

    both_endpoints = GatewayConfig(platforms={platform: _adapter_config(api_socket="/tmp/liberdusd.sock")})
    assert platform not in both_endpoints.get_connected_platforms()

    wrong_profile = GatewayConfig(platforms={platform: _adapter_config(api_socket=None, network_profile="mainnet")})
    assert platform not in wrong_profile.get_connected_platforms()


def test_liberdus_sources_preserve_agent_toolsets_for_allowed_daemon_events():
    from gateway.run import _apply_liberdus_session_tool_boundary
    from gateway.session import SessionSource

    formerly_restricted = SessionSource(
        platform=Platform("liberdus"),
        user_id="contact-test",
        user_name="test",
        chat_id="liberdus:dm:acct-general:chat-test",
        chat_topic="restricted-chat-only",
    )
    trusted = SessionSource(
        platform=Platform("liberdus"),
        user_id="contact-dbp",
        user_name="dbp",
        chat_id="liberdus:dm:acct-general:chat-dbp",
        chat_topic="allowed",
    )

    assert _apply_liberdus_session_tool_boundary(formerly_restricted, ["terminal", "web"]) == ["terminal", "web"]
    assert _apply_liberdus_session_tool_boundary(trusted, ["terminal", "web"]) == ["terminal", "web"]


@pytest.mark.asyncio
async def test_platforms_command_reports_liberdus_runtime_state():
    from gateway.run import GatewayRunner

    platform = Platform("liberdus")
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(platforms={platform: _adapter_config(api_socket=None)})
    runner.adapters = {platform: SimpleNamespace(is_connected=True)}
    runner._failed_platforms = {}

    response = await runner._handle_platforms_command(None)

    assert "Hermes Gateway Platforms" in response
    assert "Connected:** liberdus" in response
    assert "`liberdus`: connected" in response
