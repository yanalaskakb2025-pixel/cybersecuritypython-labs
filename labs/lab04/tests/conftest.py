"""Спільні фікстури: ізоляція від мережі та свіжа синтетична відповідь NVD."""

import pytest

CVE_ID = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Видаляє успадкований ключ і забороняє справжні запити Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


def make_metric(
    score=9.8,
    complexity="LOW",
    metric_type="Primary",
    source="nvd@nist.gov",
):
    """Створює новий елемент cvssMetricV31 із заданими оцінкою та складністю атаки."""
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "attackComplexity": complexity,
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "baseScore": score,
            "baseSeverity": "CRITICAL",
        },
    }


def make_payload(metrics=None, status="Analyzed", cve_id=CVE_ID):
    """Створює нову відповідь NVD з одним записом; metrics — список оцінок v3.1."""
    if metrics is None:
        metrics = [make_metric()]
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-26T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "sourceIdentifier": "training@example.invalid",
                    "vulnStatus": status,
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Synthetic vulnerability for offline API testing.",
                        }
                    ],
                    "metrics": {"cvssMetricV31": metrics},
                    "references": [],
                }
            }
        ],
    }


@pytest.fixture
def payload():
    """Новий словник синтетичної відповіді для кожного тесту."""
    return make_payload()


@pytest.fixture
def cve(payload):
    """Об'єкт cve всередині свіжої відповіді — для точкових змін у тестах."""
    return payload["vulnerabilities"][0]["cve"]
