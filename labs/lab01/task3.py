"""Завдання 3"""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""


MIN_PASSWORD_LENGTH = 10
SALT = f"{VARIANT_NUMBER:0>5}"

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_FILE_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_FILE_PATH = os.path.join(DATA_DIR, "log.json")

users_to_register = (
    ("alice_sec", "SecurePass123!"),
    ("bob_admin", "Admin#2024Pass"),
    ("charlie_dev", "DevCode99!"),
    ("diana_analyst", "Analyst2024#"),
    ("eve_hacker", "short"),
    ("frank_user", "FrankPass2024"),
    ("grace_mgr", "Graceful#1"),
    ("helen_tester", "TestPass888"),
    ("ian_guest", "GuestPass2024!"),
    ("jack_support", "Supp0rtPass!"),
)


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    data_to_hash = (password + salt).encode("utf-8")
    return hashlib.sha3_224(data_to_hash).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    hash_value = generate_hash(password, salt=SALT)
    return username, hash_value


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    valid_users = []
    for username, password in users_list:
        try:
            user_tuple = create_user(username, password)
            valid_users.append(user_tuple)
        except (ValueError, ValidationError) as e:
            print(f"[Помилка реєстрації] Користувач '{username}': {e}")

    try:
        with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "hash_value"])
            writer.writerows(valid_users)
        print(f"\n[Успіх] Базу даних збережено у {CSV_FILE_PATH}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка запису CSV] {e}")


def read_users_db() -> list[tuple[str, str]]:
    users_db = []
    try:
        with open(CSV_FILE_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header:
                for row in reader:
                    if row:
                        users_db.append((row[0], row[1]))
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка читання CSV] {e}")
        return []

    print("\n Вміст бази даних користувачів CSV ")
    print(f"{'Логін':<20} | {'Хеш пароля (SHA3-224)'}")
    print("-" * 65)
    for uname, hval in users_db:
        print(f"{uname:<20} | {hval[:25]}...")
    print("-" * 65 + "\n")

    return users_db


def log_event(func):
    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        result_status = "failure"

        try:
            res = func(username, password, *args, **kwargs)
            result_status = "success" if res else "failure"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(LOG_FILE_PATH):
                try:
                    with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    logs = []

            logs.append(log_entry)

            try:
                with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (PermissionError, OSError) as e:
                print(f"[Помилка запису логу] {e}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = read_users_db()
    users_dict = dict(users_db)

    if username not in users_dict:
        return False

    try:
        input_hash = generate_hash(password, salt=SALT)
    except (ValueError, ValidationError):
        return False

    return input_hash == users_dict[username]


def main():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    print("=== Реєстрація користувачів ===")
    create_users(users_to_register)

    read_users_db()

    print("=== Тестування автентифікації ===")
    test_cases = [
        ("alice_sec", "SecurePass123!"),
        ("alice_sec", "WrongPass123!"),
        ("unknown_user", "SomePass123!"),
        ("eve_hacker", "short"),
    ]

    for uname, pwd in test_cases:
        try:
            success = login(uname, pwd)
            status_str = "УСПІШНО" if success else "ВІДМОВА"
            print(f"Спроба входу user='{uname}': {status_str}")
        except (
            ValueError,
            ValidationError,
            FileNotFoundError,
            PermissionError,
            OSError,
        ) as e:
            print(f"Спроба входу user='{uname}': ПОМИЛКА ({e})")

    print(f"\n[Успіх] Лог подій збережено у {LOG_FILE_PATH}")


if __name__ == "__main__":
    main()