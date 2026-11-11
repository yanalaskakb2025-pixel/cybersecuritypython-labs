"""Консольна утиліта: запис NVD за ідентифікатором CVE -> JSON-звіт за варіантом.

Запуск із кореня репозиторію (локальний режим і один запит до NVD):
    python -m labs.lab04.main --cve CVE-2099-10001 \\
        --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228
"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
MIN_VARIANT = 1
MAX_VARIANT = 15

EXIT_OK = 0
EXIT_DATA_ERROR = 1
EXIT_USAGE_ERROR = 2


def cve_id_type(value: str) -> str:
    """Перевіряє повний збіг аргументу з шаблоном CVE-РРРР-NNNN (регістр важливий)."""
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"некоректний ідентифікатор CVE: {value!r} (очікувано CVE-РРРР-NNNN)"
        )
    return value


def is_valid_variant(value: object) -> bool:
    """Номер варіанта має бути цілим числом від 1 до 15 і не bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return MIN_VARIANT <= value <= MAX_VARIANT


def load_response(path: str | Path) -> object:
    """Читає локальну відповідь NVD з UTF-8 JSON-файла; повертає декодований об'єкт."""
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Звіт про вразливість із NVD за правилом варіанта.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=cve_id_type,
        help="ідентифікатор CVE, наприклад CVE-2021-44228",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="шлях до локальної відповіді NVD; із ним мережа не використовується",
    )
    return parser


def _fail(message: str) -> int:
    """Друкує пояснення помилки в stderr і повертає код 1."""
    print(f"Помилка: {message}", file=sys.stderr)
    return EXIT_DATA_ERROR


def main(argv: list[str] | None = None) -> int:
    """Розбирає аргументи, отримує відповідь, друкує звіт; повертає код завершення."""
    if not is_valid_variant(VARIANT_NUMBER):
        print(
            "Помилка: VARIANT_NUMBER у shared/student.py має бути цілим від 1 до 15.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    args = build_parser().parse_args(argv)

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    # Мережеві винятки стоять перед OSError і ValueError: RequestException успадковує
    # OSError, а requests.exceptions.JSONDecodeError є ще й ValueError.
    except requests.exceptions.Timeout:
        return _fail("перевищено час очікування відповіді NVD.")
    except requests.exceptions.ConnectionError:
        return _fail("не вдалося встановити з'єднання з NVD.")
    except requests.exceptions.HTTPError as error:
        status = (
            error.response.status_code if error.response is not None else "невідомий"
        )
        return _fail(f"NVD повернув HTTP-помилку, статус {status}.")
    except api_client.UnexpectedStatusError as error:
        return _fail(f"неочікуваний HTTP-статус {error.status_code}, очікувано 200.")
    except requests.exceptions.JSONDecodeError:
        return _fail("тіло відповіді NVD не є коректним JSON.")
    except requests.exceptions.RequestException:
        return _fail("не вдалося виконати запит до NVD.")
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return _fail(f"не вдалося прочитати файл {args.input}: {reason}.")
    except json.JSONDecodeError as error:
        return _fail(
            f"файл {args.input} не є коректним JSON "
            f"(рядок {error.lineno}, стовпець {error.colno})."
        )
    except UnicodeDecodeError:
        return _fail(f"файл {args.input} не є текстом у кодуванні UTF-8.")
    except ValueError as error:
        return _fail(f"порушено структуру даних: {error}.")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
