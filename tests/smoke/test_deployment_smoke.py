import os
import time
from typing import Any

import httpx
import pytest

BASE_URL = os.getenv("TESA_SMOKE_BASE_URL", "https://saastesa.vercel.app").rstrip("/")
TIMEOUT = 20.0
RETRIES = 3

pytestmark = pytest.mark.skipif(
    os.getenv("TESA_RUN_SMOKE") != "1",
    reason="Set TESA_RUN_SMOKE=1 to execute deployment smoke tests.",
)


def _request(method: str, path: str) -> httpx.Response:
    last_error: Exception | None = None
    url = f"{BASE_URL}{path}"

    for attempt in range(RETRIES):
        try:
            with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
                response = client.request(method, url)
                response.raise_for_status()
                return response
        except Exception as error:  # noqa: BLE001
            last_error = error
            if attempt < RETRIES - 1:
                time.sleep(1.5 * (attempt + 1))

    raise AssertionError(f"Request failed for {url}: {last_error}")


def test_smoke_health() -> None:
    response = _request("GET", "/health")
    payload = response.json()

    assert payload["status"] == "ok"


def test_smoke_summary_shape() -> None:
    response = _request("GET", "/api/v1/summary")
    payload = response.json()

    assert set(payload.keys()) == {"low", "medium", "high", "critical"}
    for value in payload.values():
        assert isinstance(value, int)
        assert value >= 0


def test_smoke_findings_shape() -> None:
    response = _request("GET", "/api/v1/findings?limit=5")
    payload = response.json()

    assert isinstance(payload, list)
    for finding in payload:
        _assert_finding_shape(finding)


def test_smoke_frontend_serves_html() -> None:
    response = _request("GET", "/")

    assert "text/html" in response.headers.get("content-type", "")
    assert "SaaS TESA" in response.text


def _assert_finding_shape(finding: dict[str, Any]) -> None:
    required_fields = {
        "finding_uid",
        "standard",
        "schema_version",
        "status",
        "severity_id",
        "severity",
        "risk_score",
        "title",
        "description",
        "category_name",
        "class_name",
        "type_name",
        "domain",
        "activity_name",
        "time",
        "source",
        "resource",
        "references",
        "raw_data",
    }

    assert required_fields.issubset(finding.keys())
    assert finding["standard"] == "OCSF"
    assert isinstance(finding["risk_score"], int)
    assert isinstance(finding["resource"], dict)
    assert isinstance(finding["references"], dict)
