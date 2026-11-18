import hashlib
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from atexit import register
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from pymongo.errors import PyMongoError

from database import (
    get_service_status,
    save_availability_check
)
from webguard.availability_fsm import AvailabilityStateMachine


logger = logging.getLogger(__name__)

MAX_MONITORED_SERVICES = 20
POLL_INTERVAL_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 5
SLOW_THRESHOLD_MS = 1000


def load_monitored_services(raw_services=None):
    if raw_services is None:
        raw_services = os.getenv("MONITORED_SERVICES_JSON", "[]")

    try:
        services = json.loads(raw_services)
    except json.JSONDecodeError as error:
        raise ValueError("MONITORED_SERVICES_JSON must contain valid JSON.") from error

    if not isinstance(services, list):
        raise ValueError("MONITORED_SERVICES_JSON must be a JSON array.")

    if len(services) > MAX_MONITORED_SERVICES:
        raise ValueError(
            f"Configure no more than {MAX_MONITORED_SERVICES} monitored services."
        )

    configured = []
    seen_urls = set()

    for service in services:
        if not isinstance(service, dict):
            raise ValueError("Each monitored service must be a JSON object.")

        name = service.get("name")
        url = service.get("url")

        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
            raise ValueError("Each monitored service needs a name up to 80 characters.")

        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"Monitored service '{name}' needs a URL.")

        url = url.strip()
        _validate_configured_url(url, name.strip())

        if url in seen_urls:
            raise ValueError(f"Duplicate monitored service URL: {url}")
        seen_urls.add(url)

        configured.append({
            "service_id": hashlib.sha256(url.encode("utf-8")).hexdigest()[:16],
            "name": name.strip(),
            "url": url
        })

    return configured


def _validate_configured_url(url, name):
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URL for monitored service '{name}'.") from error

    if (
        parsed.scheme not in ("http", "https")
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"Service '{name}' must use an HTTP(S) URL without credentials, "
            "query strings, or fragments."
        )

    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"Invalid port for monitored service '{name}'.")

    hostname = hostname.lower()
    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise ValueError(
            f"Service '{name}' must use a publicly reachable hostname."
        )

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return

    if not address.is_global:
        raise ValueError(
            f"Service '{name}' must not use a private or reserved IP address."
        )


def _assert_public_destination(url):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            port,
            type=socket.SOCK_STREAM
        )
    except OSError as error:
        raise ValueError("Service hostname could not be resolved.") from error

    resolved = {
        ipaddress.ip_address(address[4][0].split("%", 1)[0])
        for address in addresses
    }

    if not resolved or any(not address.is_global for address in resolved):
        raise ValueError("Service hostname resolves to a private or reserved address.")


def check_service(service, previous_status=None):
    previous_status = previous_status or {}
    fsm = AvailabilityStateMachine(
        state=previous_status.get("state", "Unknown"),
        recovery_attempts=previous_status.get("recovery_attempts", 0)
    )
    started_at = time.perf_counter()
    status_code = None
    error_message = None

    try:
        _assert_public_destination(service["url"])
        response = requests.get(
            service["url"],
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
            headers={"User-Agent": "WebGuard-Availability-Monitor/1.0"}
        )
        status_code = response.status_code
        successful = status_code < 400
        if not successful:
            error_message = f"HTTP {status_code}"
    except requests.Timeout:
        successful = False
        error_message = "Request timed out."
    except requests.RequestException as error:
        successful = False
        error_message = f"Request failed ({type(error).__name__})."
    except OSError:
        successful = False
        error_message = "Network error."
    except ValueError as error:
        successful = False
        error_message = str(error)

    response_time_ms = round((time.perf_counter() - started_at) * 1000, 2)
    transition = fsm.observe(
        successful=successful,
        response_time_ms=response_time_ms,
        slow_threshold_ms=SLOW_THRESHOLD_MS
    )
    checked_at = datetime.now(timezone.utc)

    check = {
        "service_id": service["service_id"],
        "name": service["name"],
        "url": service["url"],
        "state": transition["state"],
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "checked_at": checked_at,
        "recovery_attempts": transition["recovery_attempts"],
        "error": error_message
    }

    event = None
    if transition["changed"]:
        event_type = {
            "Unavailable": "failure",
            "Recovering": "recovery_started",
            "Restored": "restored"
        }.get(transition["state"], "state_changed")
        event = {
            "service_id": service["service_id"],
            "name": service["name"],
            "url": service["url"],
            "type": event_type,
            "from_state": transition["previous_state"],
            "to_state": transition["state"],
            "recovery_attempts": transition["recovery_attempts"],
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "error": error_message,
            "created_at": checked_at
        }

    return check, event


class AvailabilityMonitor:
    def __init__(self, services):
        self.services = services
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if not self.services or (
            self._thread is not None and self._thread.is_alive()
        ):
            return

        self._thread = threading.Thread(
            target=self._run,
            name="webguard-availability-monitor",
            daemon=True
        )
        self._thread.start()
        register(self.stop)

    def stop(self):
        self._stop_event.set()

    def check_all(self):
        for service in self.services:
            try:
                previous_status = get_service_status(service["service_id"])
                check, event = check_service(service, previous_status)
                save_availability_check(check, event)
                if event is not None:
                    logger.info(
                        "Service %s changed from %s to %s",
                        service["name"],
                        event["from_state"],
                        event["to_state"]
                    )
            except (PyMongoError, ValueError):
                logger.exception(
                    "Could not record availability check for %s",
                    service["name"]
                )

    def _run(self):
        while not self._stop_event.is_set():
            self.check_all()
            self._stop_event.wait(POLL_INTERVAL_SECONDS)
