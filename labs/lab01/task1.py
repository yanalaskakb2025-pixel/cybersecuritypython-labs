"""Завдання 1"""

from collections import Counter
import os
import random
import string
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Hello123!",
    "simple",
    "CompL3x@Pass",
    "password",
    "Str0ng#2023",
    "weak",
    "MySecur3!",
    "12345",
    "Advanced@1",
    "basic",
]

criteria = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "password",
    "simple",
    "weak",
    "basic",
    "12345",
    "hello",
}


def check_criteria(password: str) -> dict:
    """Перевіряє відповідність пароля основним критеріям безпеки."""
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


def evaluate_password_strength(
    password: str, password_counts: Counter
) -> str:
    """Оцінює рівень надійності пароля за алгоритмом із завдання."""
    min_length = criteria["min_length"]
    crit = check_criteria(password)

    if password in forbidden_passwords or len(password) < min_length:
        return "Заборонений"

    is_unique = password_counts[password] == 1
    if crit["all_passed"] and len(password) >= min_length + 4 and is_unique:
        return "Дуже сильний"

    if crit["all_passed"] and len(password) < min_length + 4:
        return "Сильний"

    if len(password) >= min_length:
        return "Середній"

    if (
        crit["has_digit"]
        or crit["has_upper"]
        or crit["has_lower"]
        or crit["has_special"]
    ):
        return "Слабкий"

    return "Невідомий"


def main():
    """Головна функція для виконання аналізу надійності паролів"""
    print(
        f"Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    random.seed(42)  
    duplicate_indices = [
        random.randint(0, len(passwords) - 1) for _ in range(3)
    ]
    full_passwords = passwords.copy()
    for idx in duplicate_indices:
        full_passwords.append(passwords[idx])

    password_counts = Counter(full_passwords)

    print(f"{'№':<3} | {'Пароль':<16} | {'Довжина':<8} | {'Оцінка надійності'}")
    print("-" * 52)

    for idx, pwd in enumerate(full_passwords, start=1):
        strength = evaluate_password_strength(pwd, password_counts)
        print(f"{idx:<3} | {pwd:<16} | {len(pwd):<8} | {strength}")


if __name__ == "__main__":
    main()