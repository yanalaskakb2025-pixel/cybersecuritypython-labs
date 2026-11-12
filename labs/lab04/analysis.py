"""Перевірка відповіді NVD та правило відбору за варіантом.
Функції модуля працюють лише з переданими аргументами, не читають файлів,
змінних середовища чи часу, не виконують HTTP-запитів і нічого не друкують.
"""

import math

REJECTED_STATUS = "Rejected"  # Відх запис NVD
CVSS_VERSION = "3.1"
MIN_SCORE = 0
MAX_SCORE = 10

RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

# Допустимі значення полів cvssData за специфікацією CVSS v3.1
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}


def _require(condition: bool, message: str) -> None:
    """Піднімає ValueError з поясненням, якщо умову контракту даних порушено."""
    if not condition:
        raise ValueError(message)


def _optional_text(container: dict, key: str, label: str) -> str | None:
    """Повертає None для відсутнього поля, наявне має бути непорожнім рядком."""
    if key not in container:
        return None
    value = container[key]
    is_text = isinstance(value, str) and bool(value.strip())
    _require(is_text, f"поле {label} має бути непорожнім рядком")
    return value


def _select_description(cve: dict) -> str | None:
    """Перевіряє descriptions і повертає перший непорожній опис"""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    _require(isinstance(descriptions, list), "поле descriptions має бути списком")
    selected = None
    for item in descriptions:
        _require(isinstance(item, dict), "елементи descriptions мають бути об'єктами")
        lang = item.get("lang")
        value = item.get("value")
        has_text = isinstance(lang, str) and isinstance(value, str)
        _require(has_text, "опис має містити рядки lang і value")
        if selected is None and lang == "en" and value.strip():
            selected = value
    return selected


def _select_metric(cve: dict) -> dict | None:
    """Повертає вибраний елемент cvssMetricV31 або None, якщо оцінки v3.1 немає.

    Пріоритет має перший елемент із type="Primary", якщо такого немає,
    вибирається перший елемент списку.
    """
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "поле metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    candidates = metrics["cvssMetricV31"]
    _require(isinstance(candidates, list), "поле cvssMetricV31 має бути списком")
    if not candidates:
        return None
    for item in candidates:
        _require(isinstance(item, dict), "елементи cvssMetricV31 мають бути об'єктами")
    for item in candidates:
        if item.get("type") == "Primary":
            return item
    return candidates[0]


def _check_score(score: object) -> int | float:
    """Перевіряє, що baseScore є скінченним числом від 0 до 10 і не bool."""
    is_number = isinstance(score, (int, float)) and not isinstance(score, bool)
    _require(is_number, "baseScore має бути числом")
    is_finite = not isinstance(score, float) or math.isfinite(score)
    _require(is_finite, "baseScore має бути скінченним числом")
    in_range = MIN_SCORE <= score <= MAX_SCORE
    _require(in_range, "baseScore має бути в межах від 0 до 10")
    return score


def _parse_metric(metric: dict) -> dict:
    """Перевіряє вибрану оцінку та повертає її нормалізоване подання."""
    cvss_data = metric.get("cvssData")
    _require(isinstance(cvss_data, dict), "cvssData вибраної оцінки має бути об'єктом")
    _require("baseScore" in cvss_data, "у вибраній оцінці немає baseScore")
    score = _check_score(cvss_data["baseScore"])
    version = _optional_text(cvss_data, "version", "cvssData.version")
    _require(version in (None, CVSS_VERSION), f"очікувано CVSS версії {CVSS_VERSION}")
    return {
        "version": version,
        "score": score,
        "source": _optional_text(metric, "source", "source"),
        "vector": _optional_text(cvss_data, "vectorString", "cvssData.vectorString"),
        "data": dict(cvss_data),
    }


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    None означає, що список vulnerabilities порожній, тобто CVE не знайдено.

    Формат запису:
        {
            "description": str | None,  # перший непорожній опис англійською
            "vuln_status": str | None,  # vulnStatus із відповіді
            "cvss": None | {            # вибрана оцінка CVSS v3.1
                "version": str | None,
                "score": int | float,
                "source": str | None,
                "vector": str | None,
                "data": dict,           # поверхнева копія cvssData
            },
        }

    Для статусу Rejected і для відсутнього статусу оцінки не аналізуються,
    тому "cvss" дорівнює None. Отриманий payload не змінюється.
    """
    _require(isinstance(payload, dict), "відповідь має бути JSON-об'єктом")
    _require("vulnerabilities" in payload, "у відповіді немає поля vulnerabilities")
    vulnerabilities = payload["vulnerabilities"]
    _require(isinstance(vulnerabilities, list), "vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    _require(len(vulnerabilities) == 1, "для одного CVE очікувано один запис")

    item = vulnerabilities[0]
    has_cve = isinstance(item, dict) and isinstance(item.get("cve"), dict)
    _require(has_cve, "запис має містити об'єкт cve")
    cve = item["cve"]
    _require(cve.get("id") == cve_id, "cve.id не збігається із запитаним CVE")

    vuln_status = _optional_text(cve, "vulnStatus", "vulnStatus")
    record = {
        "description": _select_description(cve),
        "vuln_status": vuln_status,
        "cvss": None,
    }
    if vuln_status is None or vuln_status == REJECTED_STATUS:
        return record

    metric = _select_metric(cve)
    if metric is not None:
        record["cvss"] = _parse_metric(metric)
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосовує правило варіанта до запису та повертає словник звіту.

    Стани перевіряються в порядку: not_found, rejected, insufficient_data,
    review, other. Поле варіанта береться з тієї самої оцінки, що й score.
    """
    is_variant = isinstance(variant, int) and not isinstance(variant, bool)
    _require(is_variant and variant in RULES, "номер варіанта має бути від 1 до 15")
    threshold, field, expected = RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == REJECTED_STATUS:
        report["decision"] = "rejected"
        return report

    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]

    if field not in cvss["data"]:
        report["decision"] = "insufficient_data"
        return report
    observed = cvss["data"][field]
    is_allowed = isinstance(observed, str) and observed in ALLOWED_VALUES[field]
    _require(is_allowed, f"поле {field} має недопустиме значення")
    report["observed"] = observed

    if cvss["score"] >= threshold and observed == expected:
        report["decision"] = "review"
    else:
        report["decision"] = "other"
    return report
