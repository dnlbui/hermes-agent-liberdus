"""Tests for the Liberdus Gateway platform adapter.

These tests use a fake liberdusd/local API only.  They intentionally avoid the
live Liberdus dev network and use sentinel strings (not real secrets) to verify
that the adapter preserves the daemon secret boundary.
"""

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

    async def post(self, path: str, json: dict[str, Any] | None = None, **_kwargs: Any) -> _FakeResponse:
        self.daemon.requests.append(("POST", path, json))
        if self.daemon.raise_on_post:
            raise httpx.ConnectError("liberdusd unavailable")
        if path == "/events/ack":
            self.daemon.acks.append(dict(json or {}))
            return _FakeResponse(200, {"ok": True, "cursor": (json or {}).get("cursor")})
        if path != "/send-requests":
            return _FakeResponse(404, {"ok": False, "error": {"code": "not_found"}})
        self.daemon.send_requests.append(dict(json or {}))
        if self.daemon.send_failure:
            return _FakeResponse(502, self.daemon.send_failure)
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
        self.acks: list[dict[str, Any]] = []
        self.raise_on_get = False
        self.raise_on_post = False
        self.send_failure: dict[str, Any] | None = None
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
    visibility: str = "normal",
    account_id: str = "acct-general",
    account_label: str = "general",
) -> dict[str, Any]:
    chat_id = chat_id or f"chat-{profile}"
    policy_mode = policy_mode or ("full" if profile == "dbp" else "restricted-chat-only")
    reply_action = reply_action or ("send-message" if profile == "dbp" else "reply-test")
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
        "capabilityClass": "owner/full" if profile == "dbp" else "restricted/chat",
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
        "reply": {"allowed": visibility == "normal", "action": reply_action},
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


def _patch_http_client(monkeypatch: pytest.MonkeyPatch, daemon: _FakeLiberdusDaemon) -> None:
    import gateway.platforms.liberdus as liberdus

    monkeypatch.setattr(liberdus.httpx, "AsyncClient", daemon.client)


@pytest.mark.asyncio
async def test_fake_daemon_inbound_policy_mapping_dedupe_and_resume(monkeypatch):
    """dbp/test become separate sessions; unknown and duplicate events are ignored."""
    from gateway.platforms.liberdus import LiberdusAdapter

    daemon = _FakeLiberdusDaemon()
    daemon.events = [
        _make_event("evt-dbp-1", "dbp", preview="dbp ping"),
        _make_event("evt-test-1", "test", preview="test ping"),
        _make_event(
            "evt-unknown-1",
            "unknown",
            chat_id="chat-unknown",
            preview="should stay quarantined",
            policy_mode="quarantine",
            reply_action="none",
            visibility="quarantine",
        ),
        _make_event("evt-mismatch-1", "test", preview="mismatched policy must not route", policy_mode="full", reply_action="send-message"),
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

    assert [event.message_id for event in delivered] == ["evt-dbp-1", "evt-test-1"]
    dbp_event, test_event = delivered
    assert dbp_event.text == "dbp ping"
    assert test_event.text == "test ping"
    assert dbp_event.source.platform.value == "liberdus"
    assert test_event.source.platform.value == "liberdus"
    assert dbp_event.source.chat_id == "liberdus:dm:acct-general:chat-dbp"
    assert test_event.source.chat_id == "liberdus:dm:acct-general:chat-test"
    assert dbp_event.source.chat_name == "Liberdus / dbp / general"
    assert test_event.source.chat_name == "Liberdus / test / general"
    assert dbp_event.source.user_name == "dbp"
    assert test_event.source.user_name == "test"
    assert dbp_event.raw_message["policyMode"] == "full"
    assert test_event.raw_message["policyMode"] == "restricted-chat-only"
    assert dbp_event.raw_message["reply"]["action"] == "send-message"
    assert test_event.raw_message["reply"]["action"] == "reply-test"
    assert "trusted full-access" in (dbp_event.channel_prompt or "")
    assert "restricted chat-only" in (test_event.channel_prompt or "")
    assert "Tool use is disabled" in (test_event.channel_prompt or "")
    assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-test-1"}]
    _assert_no_forbidden_sentinels([dbp_event, test_event])

    daemon.events.append(_make_event("evt-dbp-2", "dbp", preview="dbp resumed"))
    await adapter._poll_once()
    assert [event.message_id for event in delivered] == ["evt-dbp-1", "evt-test-1", "evt-dbp-2"]
    assert delivered[-1].source.chat_id == dbp_event.source.chat_id


@pytest.mark.asyncio
async def test_configured_account_and_counterparty_allowlists_gate_events(monkeypatch):
    """Operator allowlists can narrow daemon-visible dbp/test/account events before Hermes sees them."""
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
            counterparty_profiles=["dbp"],
        )
    )
    delivered = []

    async def handler(event):
        delivered.append(event)

    adapter.set_message_handler(handler)
    assert await adapter.connect() is True
    await adapter._poll_once()

    assert [event.message_id for event in delivered] == ["evt-dbp-allowed"]
    assert list(adapter._cursor_by_account.keys()) == ["acct-general"]
    assert delivered[0].source.chat_id == "liberdus:dm:acct-general:chat-dbp"
    assert daemon.acks == [{"schemaVersion": 1, "accountId": "acct-general", "cursor": "evt-dbp-allowed"}]


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
async def test_fake_daemon_outbound_uses_session_policy_actions(monkeypatch):
    """Replies route through /send-requests and force dbp/test actions from daemon metadata."""
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
    assert [request["action"] for request in daemon.send_requests] == ["send-message", "reply-test", "send-message"]
    assert daemon.send_requests[0]["schemaVersion"] == 1
    assert daemon.send_requests[0]["accountId"] == "acct-general"
    assert daemon.send_requests[0]["chatId"] == "chat-dbp"
    assert daemon.send_requests[0]["contactId"] == "contact-dbp"
    assert daemon.send_requests[0]["counterpartyProfile"] == "dbp"
    assert daemon.send_requests[0]["action"] == "send-message"
    assert daemon.send_requests[0]["message"] == "hello dbp"
    assert daemon.send_requests[0]["clientContext"]["platform"] == "liberdus"
    assert daemon.send_requests[0]["clientContext"]["replyToEventId"] == "evt-dbp-1"
    assert daemon.send_requests[0]["clientContext"]["policyMode"] == "full"
    assert daemon.send_requests[0]["clientContext"].get("adapterRequestId")
    assert (
        daemon.send_requests[2]["clientContext"]["adapterRequestId"]
        == daemon.send_requests[0]["clientContext"]["adapterRequestId"]
    )
    assert daemon.send_requests[1]["accountId"] == "acct-general"
    assert daemon.send_requests[1]["chatId"] == "chat-test"
    assert daemon.send_requests[1]["contactId"] == "contact-test"
    assert daemon.send_requests[1]["counterpartyProfile"] == "test"
    assert daemon.send_requests[1]["clientContext"]["policyMode"] == "restricted-chat-only"
    _assert_no_forbidden_sentinels(daemon.send_requests)


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
    monkeypatch.setenv("LIBERDUS_POLL_INTERVAL_MS", "2000")

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
    assert liberdus_config.extra["poll_interval_ms"] == 2000


def test_env_overrides_accept_http_url_alias_and_allowlists(monkeypatch):
    """Final env contract supports LIBERDUS_HTTP_URL plus account/counterparty gates."""
    monkeypatch.setenv("LIBERDUS_ENABLED", "true")
    monkeypatch.delenv("LIBERDUS_API_URL", raising=False)
    monkeypatch.setenv("LIBERDUS_HTTP_URL", "http://localhost:9484")
    monkeypatch.delenv("LIBERDUS_API_SOCKET", raising=False)
    monkeypatch.setenv("LIBERDUS_NETWORK_PROFILE", "dev")
    monkeypatch.setenv("LIBERDUS_DAEMON_API_TOKEN", "daemon-local-token")
    monkeypatch.setenv("LIBERDUS_ACCOUNT_LABELS", "general, work")
    monkeypatch.setenv("LIBERDUS_COUNTERPARTY_PROFILES", "dbp")

    config = GatewayConfig()
    _apply_env_overrides(config)

    liberdus_config = config.platforms[Platform("liberdus")]
    assert liberdus_config.extra["api_url"] == "http://localhost:9484"
    assert liberdus_config.extra["account_labels"] == ["general", "work"]
    assert liberdus_config.extra["counterparty_profiles"] == ["dbp"]
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


def test_restricted_liberdus_sources_disable_agent_toolsets():
    from gateway.run import _apply_liberdus_session_tool_boundary
    from gateway.session import SessionSource

    restricted = SessionSource(
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
        chat_topic="full",
    )

    assert _apply_liberdus_session_tool_boundary(restricted, ["terminal", "web"]) == []
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
