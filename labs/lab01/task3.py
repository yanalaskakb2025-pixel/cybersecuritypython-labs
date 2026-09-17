"""Завдання 3"""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)  # Налаштування шляху та імпорт даних студента
from shared.student import (  # Імпортує константи з файлу shared/student.py
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT,
)


class ValidationError(
    Exception
):  # Власний клас винятків, який успадковується від базового класу Exception
    """Виняток для помилок валідації пароля."""


MIN_PASSWORD_LENGTH = 10
SALT = f"{VARIANT:0>5}"  # Сіль для хешування

DATA_DIR = os.path.join(
    os.path.dirname(__file__), "data"
)  # Динамічне формування шляхів до папки data і файлів users.csv,log.json
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


def generate_hash(
    password: str, salt: str = "00000"
) -> str:  # Оголошення ф-ції генерації хешу
    if (
        password is None or salt is None or password == "" or salt == ""
    ):  # Перевірка чи пароль або сіль відсутні або є порожніми рядками
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:  # Перевірка довжини паролю
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    data_to_hash = (password + salt).encode(
        "utf-8"
    )  # Конкатинація паролю і солі і кодування рядка в байтову послідовність
    return hashlib.sha3_224(
        data_to_hash
    ).hexdigest()  # Обчислення хешу за допомогою SHA3-224 і повернення його у вигляді шістнадцяткового рядка


def create_user(
    username: str, password: str
) -> tuple[str, str]:  # Викликає користувача з сіллю і повертає логін з хешем
    hash_value = generate_hash(password, salt=SALT)
    return username, hash_value


def create_users(
    users_list: tuple[tuple[str, str], ...],
) -> None:  # Реєстрація користувачів з попереднього списку
    os.makedirs(DATA_DIR, exist_ok=True)  # Створення папки data

    valid_users = []
    for (
        username,
        password,
    ) in (
        users_list
    ):  # Цикл проходиться по кожному користувачу і перехоплює некоректні паролі
        try:
            user_tuple = create_user(username, password)
            valid_users.append(user_tuple)
        except (ValueError, ValidationError) as e:
            print(f"[Помилка реєстрації] Користувач '{username}': {e}")

    try:
        with open(
            CSV_FILE_PATH, mode="w", newline="", encoding="utf-8"
        ) as f:  # Запис успішно зареєстрованих користувачів
            writer = csv.writer(f)
            writer.writerow(["username", "hash_value"])
            writer.writerows(valid_users)
        print(f"\n[Успіх] Базу даних збережено у {CSV_FILE_PATH}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка запису CSV] {e}")


def read_users_db() -> list[
    tuple[str, str]
]:  # Зчитування користувачів з CSV_FILE_PATH та виведення їх у термінал.
    users_db = []
    try:
        with open(
            CSV_FILE_PATH, mode="r", encoding="utf-8"
        ) as f:  # Відкриває файл для читання
            reader = csv.reader(f)
            header = next(reader, None)  # Пропускає заголовок
            if header:
                for (
                    row
                ) in reader:  # Проходить по кожному рядку і заповнює список users_db
                    if row:
                        users_db.append((row[0], row[1]))
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[Помилка читання CSV] {e}")
        return []

    print("\n Вміст бази даних користувачів CSV ")  # Виведення таблиці
    print(f"{'Логін':<20} | {'Хеш пароля SHA3-224'}")
    print("-" * 65)
    for uname, hval in users_db:
        print(f"{uname:<20} | {hval[:25]}...")
    print("-" * 65 + "\n")

    return users_db


def log_event(func):  # Перехоплює виклики логів
    @functools.wraps(func)  # Зберігає назву та дані
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )  # Фіксація поточного часу та встановлення статусу спроби входу
        result_status = "failure"
        try:  # Виконання ф-ції логін, якщо повертає True то статус змінюється на success, якщо ні то failure
            res = func(username, password, *args, **kwargs)
            result_status = "success" if res else "failure"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:  # Формується словник з даними про спроби входу
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(
                LOG_FILE_PATH
            ):  # Зчитує існуючий файл JSON логів і додає новий запис логів у список
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
def login(username: str, password: str) -> bool:  # Оголошення автентифікації
    if not username or not password:  # Перевірка порожніх значень
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = read_users_db()  # Зчитування бази даних CSV
    users_dict = dict(users_db)  # Перетворення списку в словник для швидкого пошуку

    if username not in users_dict:  # Якщо немає в словнику
        return False

    try:
        input_hash = generate_hash(
            password, salt=SALT
        )  # Хешування введеного пароля з сіллю
    except (ValueError, ValidationError):
        return False  # Якщо обчислений хеш не збігається з збереженим у CSV базі

    return input_hash == users_dict[username]


def main():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT}\n"  # Вивід даних
    )
    print("Реєстрація користувачів")
    create_users(users_to_register)  # Запуск створення CSV бази і вивід вмісту

    read_users_db()

    print("Тестування автентифікації")
    test_cases = [  # Створення тестових куйсів для перевірки всіх варіантів
        ("alice_sec", "SecurePass123!"),
        ("alice_sec", "WrongPass123!"),
        ("unknown_user", "SomePass123!"),
        ("eve_hacker", "short"),
    ]

    for uname, pwd in test_cases:  # Проходить по всіх кейсах
        try:
            success = login(uname, pwd)  # Викликає логін
            status_str = "УСПІШНО" if success else "ВІДМОВА"
            print(f"Спроба входу user='{uname}': {status_str}")
        except (  # Обробляє винятки
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
