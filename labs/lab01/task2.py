"""Завдання 2"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "sysadmin02": {
        "role": "system_admin",
        "clearance": 4,
        "department": "Infrastructure",
        "active": True,
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

resources = [
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

security_levels = ("Open", "Internal", "Restricted", "Top Secret")
blocked_users = {"external123", "old_account", "test_user"}


def check_access(username: str, resource_level: int) -> tuple[str, str | None]:
   
    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user_info = users[username]
    if not user_info["active"]:
        return "DENY", "Account inactive"

    if user_info["clearance"] >= resource_level:
        return "ALLOW", None

    return "DENY", "Insufficient clearance"


def main():
    """Головна функція запуску системи контролю доступу."""
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    print("=== Список ресурсів системи ===")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<16} | Рівень безпеки: {level_name}")
    print("\n" + "=" * 60 + "\n")

    all_users_to_check = set(users.keys()) | blocked_users

    print("=== Результати перевірки доступу ===")
    for username in sorted(all_users_to_check):
        for res_name, res_level in resources:
            status, reason = check_access(username, res_level)
            if status == "ALLOW":
                print(f"user=[{username}] resource=[{res_name}] -> ALLOW")
            else:
                print(f"user=[{username}] resource=[{res_name}] -> DENY ({reason})")


if __name__ == "__main__":
    main()
