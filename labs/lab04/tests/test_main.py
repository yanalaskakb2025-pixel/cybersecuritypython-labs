"""Тести CLI: коди завершення, stdout, stderr, локальний і мережевий режими."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.conftest import CVE_ID, make_metric, make_payload

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
FAKE_KEY = "fake-key-for-tests-0000"


@pytest.fixture
def no_network(monkeypatch):
    """Двійник fetch_response дає перевірити, що клієнт не викликався"""
    fake_fetch = Mock(side_effect=AssertionError("мережевий запит у локальному режимі"))
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    return fake_fetch


def write_json(tmp_path, data):
    path = tmp_path / "response.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_local_run_with_sample_file(capsys, no_network):
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == {
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
    no_network.assert_not_called()


@pytest.mark.parametrize(
    "score, expected",
    [(7.9, "other"), (8.0, "review"), (8.1, "review")],
)
def test_local_run_threshold_boundary(tmp_path, capsys, no_network, score, expected):
    path = write_json(tmp_path, make_payload([make_metric(score=score)]))

    code = main.main(["--cve", CVE_ID, "--input", str(path)])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == expected


def test_local_run_not_found_is_success(tmp_path, capsys, no_network):
    path = write_json(tmp_path, {"totalResults": 0, "vulnerabilities": []})

    code = main.main(["--cve", CVE_ID, "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["decision"] == "not_found"
    assert captured.err == ""


def test_output_keeps_non_ascii_text(tmp_path, capsys, no_network):
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Опис — тест"
    path = write_json(tmp_path, payload)

    main.main(["--cve", CVE_ID, "--input", str(path)])

    assert "Опис — тест" in capsys.readouterr().out


def test_invalid_json_file(tmp_path, capsys, no_network):
    path = tmp_path / "broken.json"
    path.write_text('{"vulnerabilities": [', encoding="utf-8")

    code = main.main(["--cve", CVE_ID, "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "не є коректним JSON" in captured.err
    assert "Traceback" not in captured.err


def test_missing_file(tmp_path, capsys, no_network):
    code = main.main(["--cve", CVE_ID, "--input", str(tmp_path / "absent.json")])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "не вдалося прочитати файл" in captured.err


def test_non_utf8_file(tmp_path, capsys, no_network):
    path = tmp_path / "latin.json"
    path.write_bytes(b'{"vulnerabilities": "\xff\xfe"}')

    code = main.main(["--cve", CVE_ID, "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "UTF-8" in captured.err


def test_structure_error_in_file(tmp_path, capsys, no_network):
    path = write_json(tmp_path, {"vulnerabilities": None})

    code = main.main(["--cve", CVE_ID, "--input", str(path)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "порушено структуру даних" in captured.err


def test_cve_argument_must_match_file(capsys, no_network):
    code = main.main(["--cve", "CVE-2099-10002", "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "cve.id" in captured.err


def test_load_response_returns_decoded_object(tmp_path):
    path = write_json(tmp_path, {"vulnerabilities": []})

    assert main.load_response(path) == {"vulnerabilities": []}


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--input", "file.json"],
        ["--cve", "cve-2099-10001"],
        ["--cve", "CVE-2099-123"],
        ["--cve", "CVE-99-10001"],
        ["--cve", "CVE-2099-10001 "],
        ["--cve", "xCVE-2099-10001"],
        ["--cve", "CVE-2099-10001\n"],
        ["--cve", CVE_ID, "--unknown"],
    ],
)
def test_invalid_arguments_exit_with_code_2(capsys, no_network, argv):
    with pytest.raises(SystemExit) as exception:
        main.main(argv)

    captured = capsys.readouterr()
    assert exception.value.code == 2
    assert captured.out == ""
    assert captured.err != ""
    no_network.assert_not_called()


@pytest.mark.parametrize("variant", [0, 16, -2, True, "2", 2.0, None])
def test_invalid_variant_number_returns_code_2(
    monkeypatch, capsys, no_network, variant
):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)

    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "VARIANT_NUMBER" in captured.err


def test_other_variant_changes_rule(monkeypatch, capsys, no_network):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 15)

    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])

    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["variant"] == 15
    assert report["decision"] == "other"


# Мережевий режим із підміною функції клієнта


def test_network_mode_calls_client_once(monkeypatch, capsys):
    fake_fetch = Mock(return_value=make_payload())
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)

    code = main.main(["--cve", CVE_ID])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "review"
    fake_fetch.assert_called_once_with("CVE-2099-10001")


def http_error(status_code):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    return requests.exceptions.HTTPError("secret body text", response=response)


@pytest.mark.parametrize(
    "error, fragment",
    [
        (requests.exceptions.ConnectTimeout("t"), "час очікування"),
        (requests.exceptions.ReadTimeout("t"), "час очікування"),
        (requests.exceptions.ConnectionError("c"), "з'єднання"),
        (http_error(404), "404"),
        (http_error(503), "503"),
        (api_client.UnexpectedStatusError(302), "302"),
        (
            requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1),
            "не є коректним JSON",
        ),
        (requests.exceptions.TooManyRedirects("r"), "не вдалося виконати запит"),
    ],
)
def test_network_errors_return_code_1(monkeypatch, capsys, error, fragment):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))

    code = main.main(["--cve", CVE_ID])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert fragment in captured.err
    assert "Traceback" not in captured.err
    assert "secret body text" not in captured.err


def test_http_404_is_not_reported_as_not_found(monkeypatch, capsys):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=http_error(404)))

    code = main.main(["--cve", CVE_ID])

    captured = capsys.readouterr()
    assert code == 1
    assert "not_found" not in captured.out


def test_programming_errors_are_not_hidden(monkeypatch):
    # Немає except Exception: непередбачена помилка програми не маскується кодом 1.
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=KeyError("bug")))

    with pytest.raises(KeyError):
        main.main(["--cve", CVE_ID])


# Інтеграція CLI + справжній клієнт із підміною requests.get


def test_cli_with_real_client_and_fake_get(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = make_payload([make_metric(score=8.0)])
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    code = main.main(["--cve", CVE_ID])

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["decision"] == "review"
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json", "apiKey": FAKE_KEY},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    # Ключ не потрапляє ні у звіт ні в повідомлення.
    assert FAKE_KEY not in captured.out
    assert FAKE_KEY not in captured.err
