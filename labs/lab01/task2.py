"""Завдання 2"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))  # Налаштування шляху та імпорт даних студента
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT  # Імпортує константи з файлу shared/student.py

users = {  # Список з даними користувачів
    "sysadmin02": {
        "role": "system_admin",  # Роль
        "clearance": 4,  # Рівень допуску
        "department": "Infrastructure",  # Відділ 
        "active": True,  # Статус облікогового запису
    },
    "analyst234": {
        "role": "security_analyst",
        "clearance": 3,
        "department": "SOC",
        "active": True,
    },
    "developer567": {
        "role": "developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "intern890": {
        "role": "intern",
        "clearance": 1,
        "department": "HR",
        "active": True,
    },
    "external123": {
        "role": "external",
        "clearance": 1,
        "department": "Vendor",
        "active": False,
    },
}

resources = [  # Список кортежів із назвою ресурсу та його числовим рівнем безпеки
    ("prod_database", 4),
    ("dev_environment", 2),
    ("documentation", 1),
    ("source_code", 3),
    ("server_configs", 4),
    ("test_data", 2),
    ("compliance_docs", 3),
    ("system_logs", 4),
    ("project_files", 2),
    ("public_wiki", 1),
]

security_levels = ("Open", "Internal", "Restricted", "Top Secret")  # Рівні безпеки
blocked_users = {"external123", "old_account", "test_user"}  # Заблоковані користувачі

def check_access(username: str, resource_level: int) -> tuple[str, str | None]:     # Перевірка чи користувач заблокований
    if username in blocked_users:
        return "DENY", "User is blocked"

    if username not in users:    # Чи є він у системі
        return "DENY", "User not found"

    user_info = users[username] # Перевірка статусу облікового запису
    if not user_info["active"]:
        return "DENY", "Account inactive"

    if user_info["clearance"] >= resource_level:  # Перевірка рівню допуску
        return "ALLOW", None

    return "DENY", "Insufficient clearance" 

def main():  # Головна функція запуску системи контролю доступу
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT}\n"
    )

    print("Список ресурсів системи")
    for res_name, res_level in resources:  # Проходить по списку ресурсів і перетворює числовий рівень у текстову назву
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<16} | Рівень безпеки: {level_name}")
    print("\n" + "=" * 60 + "\n")

    all_users_to_check = set(users.keys()) | blocked_users # Об'єднання та перевірка користувачів з двох баз

    print("Результат перевірки доступу")
    for username in sorted(all_users_to_check): # Перевірка доступу кожного користувача до кожного ресурсу і сортує в алфавітному порядку
        for res_name, res_level in resources:   # По поточному користувачі проходить по всьому списку ресурсу
            status, reason = check_access(username, res_level) 
            if status == "ALLOW":
                print(f"user=[{username}] resource=[{res_name}] -> ALLOW")
            else:
                print(f"user=[{username}] resource=[{res_name}] -> DENY ({reason})")

if __name__ == "__main__":
    main()