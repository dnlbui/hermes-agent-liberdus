from hermes_cli.gateway import _PLATFORMS, _platform_status, _runtime_health_lines


def test_runtime_health_lines_include_fatal_platform_and_startup_reason(monkeypatch):
    monkeypatch.setattr(
        "gateway.status.read_runtime_status",
        lambda: {
            "gateway_state": "startup_failed",
            "exit_reason": "telegram conflict",
            "platforms": {
                "telegram": {
                    "state": "fatal",
                    "error_message": "another poller is active",
                }
            },
        },
    )

    lines = _runtime_health_lines()

    assert "⚠ telegram: another poller is active" in lines
    assert "⚠ Last startup issue: telegram conflict" in lines


def test_runtime_health_lines_include_connected_and_retrying_platforms(monkeypatch):
    monkeypatch.setattr(
        "gateway.status.read_runtime_status",
        lambda: {
            "gateway_state": "running",
            "platforms": {
                "liberdus": {"state": "connected"},
                "signal": {"state": "retrying", "error_code": "daemon_unavailable"},
            },
        },
    )

    lines = _runtime_health_lines()

    assert "✓ liberdus: connected" in lines
    assert "⚠ signal: retrying (daemon_unavailable)" in lines


def test_liberdus_platform_setup_status_requires_local_dev_endpoint(monkeypatch):
    liberdus = next(platform for platform in _PLATFORMS if platform["key"] == "liberdus")
    monkeypatch.setenv("LIBERDUS_ENABLED", "true")
    monkeypatch.setenv("LIBERDUS_API_URL", "http://127.0.0.1:9484")
    monkeypatch.delenv("LIBERDUS_API_SOCKET", raising=False)
    monkeypatch.setenv("LIBERDUS_NETWORK_PROFILE", "dev")
    assert _platform_status(liberdus) == "configured"

    monkeypatch.setenv("LIBERDUS_API_URL", "https://liberdus.com/dev")
    assert _platform_status(liberdus) == "partially configured"

    monkeypatch.delenv("LIBERDUS_API_URL", raising=False)
    monkeypatch.setenv("LIBERDUS_API_SOCKET", "relative.sock")
    assert _platform_status(liberdus) == "partially configured"
