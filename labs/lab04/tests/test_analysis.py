"""Модульні тести перевірки відповіді та правила варіанта 2.

Правило: baseScore >= 8.0 і attackComplexity == "LOW" 
"""

import copy

import pytest

from labs.lab04 import analysis
from labs.lab04.tests.conftest import CVE_ID, make_metric, make_payload

VARIANT = 2


def report_for(payload, variant=VARIANT):
    """Проганяє відповідь через обидві функції аналізу."""
    record = analysis.extract_record(payload, CVE_ID)
    return analysis.build_report(record, CVE_ID, variant)

@pytest.mark.parametrize(
    "score, complexity, expected",
    [
        (7.9, "LOW", "other"),  # нижче порога за відповідної ознаки
        (8.0, "LOW", "review"),  # рівно на порозі: умова >=, а не >
        (8.1, "LOW", "review"),  # вище порога
        (9.8, "LOW", "review"),
        (9.8, "HIGH", "other"),  # висока оцінка, але невідповідна ознака
        (8.0, "HIGH", "other"),
        (0, "LOW", "other"),  # нижня межа допустимого діапазону
        (10, "LOW", "review"),  # верхня межа, ціле число
    ],
)
def test_decision_for_score_and_complexity(score, complexity, expected):
    payload = make_payload([make_metric(score=score, complexity=complexity)])

    report = report_for(payload)

    assert report["decision"] == expected
    assert report["score"] == score
    assert report["observed"] == complexity


def test_report_contains_all_fields(payload):
    assert report_for(payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 2,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
        "observed": "LOW",
        "decision": "review",
    }


def test_sample_gives_other_for_variant_15(payload):
    report = report_for(payload, variant=15)

    assert report["decision"] == "other"
    assert report["rule"] == {
        "threshold": 8.0,
        "field": "attackComplexity",
        "expected": "HIGH",
    }


def test_not_found_for_empty_list(payload):
    payload["vulnerabilities"] = []

    assert analysis.extract_record(payload, CVE_ID) is None
    assert report_for(payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 2,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score(cve, payload):
    cve["vulnStatus"] = "Rejected"

    report = report_for(payload)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["cvss_version"] is None
    assert report["score_source"] is None
    assert report["vector"] is None
    assert report["observed"] is None


def test_rejected_does_not_analyse_broken_metrics(cve, payload):
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = None

    assert report_for(payload)["decision"] == "rejected"


def test_missing_status_gives_insufficient_data(cve, payload):
    del cve["vulnStatus"]

    report = report_for(payload)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize("case", ["no_metrics", "no_v31", "empty_v31"])
def test_missing_score_gives_insufficient_data(cve, payload, case):
    if case == "no_metrics":
        del cve["metrics"]
    elif case == "no_v31":
        cve["metrics"] = {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]}
    else:
        cve["metrics"]["cvssMetricV31"] = []

    report = report_for(payload)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_variant_field_gives_insufficient_data(cve, payload):
    del cve["metrics"]["cvssMetricV31"][0]["cvssData"]["attackComplexity"]

    report = report_for(payload)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None
    assert report["score"] == 9.8


@pytest.mark.parametrize("value", [None, "MEDIUM", "low", "", 1, True, ["LOW"]])
def test_invalid_variant_field_raises(cve, payload, value):
    cve["metrics"]["cvssMetricV31"][0]["cvssData"]["attackComplexity"] = value

    with pytest.raises(ValueError):
        report_for(payload)


@pytest.mark.parametrize(
    "score",
    ["9.8", True, False, None, float("nan"), float("inf"), -0.1, 10.1, [9.8]],
)
def test_invalid_score_raises(cve, payload, score):
    cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = score

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_missing_score_in_selected_metric_raises(cve, payload):
    del cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "bad_payload",
    [
        None,
        [],
        "text",
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": ["text"]},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": None}]},
        {"vulnerabilities": [{"cve": {}}]},
    ],
)
def test_invalid_payload_structure_raises(bad_payload):
    with pytest.raises(ValueError):
        analysis.extract_record(bad_payload, CVE_ID)


def test_more_than_one_record_raises(payload):
    payload["vulnerabilities"].append(copy.deepcopy(payload["vulnerabilities"][0]))

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_mismatched_cve_id_raises():
    payload = make_payload(cve_id="CVE-2099-10002")

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize("status", [None, "", "   ", 5])
def test_invalid_status_raises(cve, payload, status):
    cve["vulnStatus"] = status

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "metrics",
    [
        None,
        [],
        "text",
        {"cvssMetricV31": None},
        {"cvssMetricV31": {}},
        {"cvssMetricV31": [1]},
    ],
)
def test_invalid_metrics_structure_raises(cve, payload, metrics):
    cve["metrics"] = metrics

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize("cvss_data", [None, [], "text"])
def test_invalid_cvss_data_raises(cve, payload, cvss_data):
    cve["metrics"]["cvssMetricV31"][0]["cvssData"] = cvss_data

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "descriptions",
    [None, {}, ["text"], [{"lang": "en"}], [{"lang": 1, "value": "x"}]],
)
def test_invalid_descriptions_raise(cve, payload, descriptions):
    cve["descriptions"] = descriptions

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize("version", ["3.0", "4.0", "", None, 3.1])
def test_invalid_cvss_version_raises(cve, payload, version):
    cve["metrics"]["cvssMetricV31"][0]["cvssData"]["version"] = version

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize("variant", [0, 16, -1, True, "2", 2.0, None])
def test_invalid_variant_raises(payload, variant):
    record = analysis.extract_record(payload, CVE_ID)

    with pytest.raises(ValueError):
        analysis.build_report(record, CVE_ID, variant)


def test_primary_has_priority_over_preceding_secondary():
    payload = make_payload(
        [
            make_metric(
                score=9.9,
                complexity="LOW",
                metric_type="Secondary",
                source="vendor@example.invalid",
            ),
            make_metric(score=5.0, complexity="HIGH", metric_type="Primary"),
        ]
    )

    report = report_for(payload)

    # Secondary дав би review правильний вибір Primary дає other.
    assert report["score"] == 5.0
    assert report["observed"] == "HIGH"
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "other"


def test_first_metric_is_used_without_primary():
    payload = make_payload(
        [
            make_metric(
                score=8.5,
                complexity="LOW",
                metric_type="Secondary",
                source="first@example.invalid",
            ),
            make_metric(
                score=3.0,
                complexity="HIGH",
                metric_type="Secondary",
                source="second@example.invalid",
            ),
        ]
    )

    report = report_for(payload)

    assert report["score"] == 8.5
    assert report["score_source"] == "first@example.invalid"
    assert report["decision"] == "review"


def test_unselected_metrics_are_not_analysed():
    broken = make_metric(metric_type="Secondary")
    broken["cvssData"]["baseScore"] = "broken"
    payload = make_payload([make_metric(score=8.0), broken])

    assert report_for(payload)["decision"] == "review"

def test_optional_fields_become_none(cve, payload):
    metric = cve["metrics"]["cvssMetricV31"][0]
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    del cve["descriptions"]

    report = report_for(payload)

    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["description"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize("key", ["vectorString", "source"])
def test_present_optional_field_must_be_non_empty_string(cve, payload, key):
    metric = cve["metrics"]["cvssMetricV31"][0]
    target = metric if key == "source" else metric["cvssData"]
    target[key] = ""

    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_first_non_empty_english_description_is_selected(cve, payload):
    cve["descriptions"] = [
        {"lang": "es", "value": "Descripcion sintetica."},
        {"lang": "en", "value": ""},
        {"lang": "en", "value": "First English text."},
        {"lang": "en", "value": "Second English text."},
    ]

    assert report_for(payload)["description"] == "First English text."


def test_description_is_none_without_english_text(cve, payload):
    cve["descriptions"] = [{"lang": "es", "value": "Descripcion sintetica."}]

    assert report_for(payload)["description"] is None


def test_payload_is_not_modified(payload):
    original = copy.deepcopy(payload)

    report_for(payload)

    assert payload == original
