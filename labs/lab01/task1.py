"""Завдання 1"""

import os
import random
import string
import sys
from collections import (
    Counter,  # Kлас, який підраховує кількість повторень елементів у списку
)

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )  # Налаштування шляху та імпорт даних студента
)

from shared.student import (  # Імпортує константи з файлу shared/student.py
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT,
)

passwords = [
    "Hello123!",
    "simple",
    "CompL3x@Pass",
    "password",
    "Str0ng#2023",  # Вихфдний список паролів
    "weak",
    "MySecur3!",
    "12345",
    "Advanced@1",
    "basic",
    "QQQ"
]

criteria = {
    "min_length": 10,
    "require_digits": True,  # Параметри вимог до безпеки паролю
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "password",
    "simple",
    "weak",  # Заборонені паролі
    "basic",
    "12345",
    "hello",
}


def check_criteria(password: str) -> dict:  # Перевірка пароля щодо зазначених критеріїв
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    return {
        "has_digit": has_digit,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_special": has_special,
        "all_passed": has_digit and has_upper and has_lower and has_special,
    }


def evaluate_password_strength(  # Перевірка на індивідуальність
    password: str, password_counts: Counter
) -> str:
    """Оцінює рівень надійності пароля за алгоритмом із завдання."""
    min_length = criteria["min_length"]  # Мінімальна довжина
    crit = check_criteria(password)

    if (
        password in forbidden_passwords or len(password) < min_length
    ):  # Якщо пароль є у списку заборонених або його довжина менша за 10 символів
        return "Заборонений"

    is_unique = (
        password_counts[password] == 1
    )  # Якщо пароль зустрічається у списку точно 1 раз
    if (
        crit["all_passed"] and len(password) >= min_length + 4 and is_unique
    ):  # Дотримані всі критерії, довжина >=14 і пароль є унікальний
        return "Дуже сильний"

    if (
        crit["all_passed"] and len(password) < min_length + 4
    ):  # Дотримані всі критерії але довжина <14
        return "Сильний"

    if len(password) >= min_length:  # Якщо довжина паролю більша за 10
        return "Середній"

    if (  # Якщо не відповідає одному з критеріїв
        crit["has_digit"]
        or crit["has_upper"]
        or crit["has_lower"]
        or crit["has_special"]
    ):
        return "Слабкий"

    return "Невідомий"  # Якщо жодна з умов не спрацювала


def main():  # Головна функція для аналізу надійності паролів
    print(f"Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT}\n")

    random.seed(10)  # Фіксує випадковість
    duplicate_indices = [
        random.randint(0, len(passwords) - 1)
        for _ in range(
            3
        )  # Генерує 3 випадкові індекси зі списку паролів для створення дублікатів
    ]
    full_passwords = (
        passwords.copy()
    )  # Створює копію списку паролів і додає до неї 3 скопійованих паролі
    for idx in duplicate_indices:
        full_passwords.append(passwords[idx])

    password_counts = Counter(
        full_passwords
    )  # Підраховує кількість повторень кожного пароля

    print(f"{'№':<3} | {'Пароль':<16} | {'Довжина':<8} | {'Оцінка надійності'}")
    print("-" * 52)

    for idx, pwd in enumerate(
        full_passwords, start=1
    ):  # Цикл проходить по кожному паролю і оцінює за зазначеними критеріями
        strength = evaluate_password_strength(pwd, password_counts)
        print(f"{idx:<3} | {pwd:<16} | {len(pwd):<8} | {strength}")


if __name__ == "__main__":
    main()
