"""Тести HTTP-клієнта: підмінюється лише requests.get, код клієнта справжній."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"
FAKE_KEY = "fake-key-for-tests-0000"


def make_response(status_code=200, payload=None):
    """Двійник requests.Response з підготовленим тілом."""
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


# --- build_headers ---


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_ignore_blank_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)

    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_key_strip_spaces(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", f"  {FAKE_KEY}\n")

    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": FAKE_KEY,
    }


def test_key_is_read_at_call_time(monkeypatch):
    # Ключ задано вже після імпорту модуля, отже читання відбувається під час виклику.
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    assert api_client.build_headers()["apiKey"] == FAKE_KEY


# --- fetch_response: успішний запит ---


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE_ID) == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_in_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    fake_get = Mock(return_value=make_response(payload={"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE_ID)

    args, kwargs = fake_get.call_args
    assert kwargs["headers"] == {"Accept": "application/json", "apiKey": FAKE_KEY}
    assert kwargs["params"] == {"cveId": "CVE-2099-10001"}
    assert FAKE_KEY not in args[0]


# --- fetch_response: помилки ---


@pytest.mark.parametrize("status_code", [403, 404, 429, 500, 503])
def test_fetch_propagates_http_error(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    # Сам status_code не піднімає виняток у двійника — задаємо side_effect явно.
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.HTTPError) as exception:
        api_client.fetch_response(CVE_ID)

    assert exception.value.response.status_code == status_code
    response.json.assert_not_called()


@pytest.mark.parametrize("status_code", [204, 301, 302])
def test_fetch_rejects_unexpected_status(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(api_client.UnexpectedStatusError) as exception:
        api_client.fetch_response(CVE_ID)

    assert exception.value.status_code == status_code
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ReadTimeout,
        requests.exceptions.ConnectionError,
    ],
)
def test_fetch_propagates_network_error(monkeypatch, error):
    fake_get = Mock(side_effect=error("synthetic failure"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(error):
        api_client.fetch_response(CVE_ID)

    # Автоматичних повторів немає: рівно один виклик.
    assert fake_get.call_count == 1


def test_fetch_propagates_invalid_json(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE_ID)


def test_real_network_is_blocked():
    # Перевірка самої фікстури isolated_environment: без підміни запит неможливий.
    with pytest.raises(AttributeError):
        api_client.fetch_response(CVE_ID)
