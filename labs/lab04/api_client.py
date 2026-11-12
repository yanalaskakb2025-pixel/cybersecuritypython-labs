"""Клієнт NVD CVE API 2.0: заголовки та один GET-запит за ідентифікатором CVE.
Модуль лише отримує дані. Семантичну перевірку відповіді виконує analysis.py,
а повідомлення про помилки формує main.py.
"""

import os

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
TIMEOUT = (3.05, 10)  # Час встановлення з'єднання, час очікування між отриманням даних
EXPECTED_STATUS = 200


class UnexpectedStatusError(Exception):
    """Якщо сервер відповів без HTTP-помилки, але не статусом 200"""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"unexpected HTTP status {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту apiKey додається лише за непорожнього NVD_API_KEY."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv(API_KEY_ENV, "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> object:
    """Виконує один GET-запит до NVD і повертає декодоване JSON-тіло відповіді"""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != EXPECTED_STATUS:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
