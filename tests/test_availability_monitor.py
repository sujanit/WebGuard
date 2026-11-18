import json
import socket

import pytest

from webguard import availability_monitor


def test_load_monitored_services_generates_stable_ids():
    raw = json.dumps([
        {"name": "Public API", "url": "https://api.example.com/health"}
    ])

    first_load = availability_monitor.load_monitored_services(raw)
    second_load = availability_monitor.load_monitored_services(raw)

    assert first_load == second_load
    assert first_load[0]["name"] == "Public API"
    assert len(first_load[0]["service_id"]) == 16


@pytest.mark.parametrize(
    "url",
    [
        "ftp://api.example.com/",
        "http://127.0.0.1/health",
        "https://user:password@api.example.com/health",
        "https://api.example.com/health?token=secret"
    ]
)
def test_load_monitored_services_rejects_unsafe_urls(url):
    raw = json.dumps([{"name": "API", "url": url}])

    with pytest.raises(ValueError):
        availability_monitor.load_monitored_services(raw)


def test_load_monitored_services_rejects_invalid_json():
    with pytest.raises(ValueError, match="valid JSON"):
        availability_monitor.load_monitored_services("{")


def test_check_service_records_latency_and_disables_redirects(monkeypatch):
    service = {
        "service_id": "service-1",
        "name": "API",
        "url": "https://api.example.com/health"
    }
    request_options = {}
    timestamps = iter([1.0, 2.25])

    class FakeResponse:
        status_code = 200

    monkeypatch.setattr(
        availability_monitor,
        "_assert_public_destination",
        lambda url: None
    )
    monkeypatch.setattr(
        availability_monitor.requests,
        "get",
        lambda url, **kwargs: request_options.update(kwargs) or FakeResponse()
    )
    monkeypatch.setattr(
        availability_monitor.time,
        "perf_counter",
        lambda: next(timestamps)
    )

    check, event = availability_monitor.check_service(service)

    assert check["state"] == "Slow"
    assert check["response_time_ms"] == 1250
    assert check["status_code"] == 200
    assert request_options["allow_redirects"] is False
    assert event["to_state"] == "Slow"


def test_check_service_blocks_private_dns_results(monkeypatch):
    service = {
        "service_id": "service-1",
        "name": "API",
        "url": "https://api.example.com/health"
    }
    request_called = False

    def resolve_private_address(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.0.0.1", 443)
            )
        ]

    def unexpected_request(*args, **kwargs):
        nonlocal request_called
        request_called = True
        raise AssertionError("Private destinations must not be requested.")

    monkeypatch.setattr(
        availability_monitor.socket,
        "getaddrinfo",
        resolve_private_address
    )
    monkeypatch.setattr(
        availability_monitor.requests,
        "get",
        unexpected_request
    )

    check, _ = availability_monitor.check_service(service)

    assert check["state"] == "Unavailable"
    assert check["error"] == (
        "Service hostname resolves to a private or reserved address."
    )
    assert request_called is False
