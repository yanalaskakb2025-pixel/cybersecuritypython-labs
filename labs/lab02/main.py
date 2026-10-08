import sys
from datetime import timedelta

from labs.lab02.task1 import Admin, Session, User, UserAccount


def run_demo() -> None:
    print("Завдання 1")
    # Створення користувача та адміна
    print("\nСтворення користувача та адміністратора!")
    user = User("bana_nas", "bana_nas@example.com", password="Bananas#1") 
    print(f"Створено користувача: {user}")

    admin = Admin(
        "admin_user", "admin@example.com", password="AdminPassword123!", permissions=["ban_ip", "read_logs"]  # Нaслідувач user з додатковими правами
    )
    print(f"Створено адміністратора: {admin}")
    print("\n Зміна email з валідацією ")
    user.email = "new_email@example.com"
    print(f"Новий валідний email {user.email}")
    
    invalid_emails = ["wrong_email_format", "a.b@lpnu.ua", "1abc@lpnu.ua"] # Валідація пошти (сеттер, інкапсуляція)
    for email in invalid_emails:
        try:
            user.email = email
        except ValueError as e:
            print(f"Помилка валідації: {e}")

    print("\nПеревірка прав адміністратора")
    admin.grant_permission("manage_firewall") # Додавання права керувати фаєрволом
    print(f"Після надання права 'manage_firewall': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}")  # Перевірка

    admin.revoke_permission("ban_ip")  # Скасування дозволу
    print(f"Після відкликання 'ban_ip': {admin}")
    print(f"Перевірка has_permission('ban_ip'): {admin.has_permission('ban_ip')}")

    print("\nРобота з UserAccount, сесією та таймаутом")
    account = UserAccount(user)

    # Невдалий вхід
    res_fail = account.login("bana_nas", "WrongPassword", "127.0.0.1")
    print(f"Невдалий вхід: result={res_fail}, is_authenticated={account.is_authenticated()}")

    # Успішний вхід
    res_success = account.login("bana_nas", "Bananas#1", "127.0.0.1")
    print(f"Успішний вхід: result={res_success}, is_authenticated={account.is_authenticated()}")

    # Доступ через спецметод __getitem__ у класі ЮзерАкаунт
    print(f"Доступ через спецметод account['user']: {account['user']}")

    # Таймаут сесії 
    if account.session:
        account.session.last_activity = account.session.last_activity - timedelta(seconds=901)
    print(f"Після закінчення таймауту: is_authenticated={account.is_authenticated()}")

    # Оновлюємо сесію для виходу
    account.login("bana_nas", "Bananas#1", "127.0.0.1")
    account.logout()
    print(f"Після виходу (logout): is_authenticated={account.is_authenticated()}")

    # Захист __getitem__ / __setitem__  інкапсуляція
    print("\nЗахист __getitem__ / __setitem__")
    try:
        _ = account["password_hash"]
    except KeyError as e:
        print(f"KeyError (заборонений ключ): {e}")

    try:
        account["session"] = "неправильний тип"
    except TypeError as e:
        print(f"TypeError (хибний тип): {e}")

    new_session = Session("127.0.0.1")
    account["session"] = new_session
    print(f"Коректне присвоєння account['session']: {account['session']}")

    print("\nЖурнал аудиту")
    for entry in account.audit_log.entries:
        ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")

    # Якщо користувач без пароля 
    print("\nКористувач без пароля")
    noname_user = User("noname", "noname@lpnu.ua", password="")
    print(f"Створено: {noname_user}")
    noname_admin = Admin("noname_admin", "admin_noname@lpnu.ua", password="", permissions=["read_logs"])
    print(f"Створено: {noname_admin}")

    noname_account = UserAccount(noname_user)
    login_res = noname_account.login("noname", "", "127.0.0.1")
    print(f"Спроба входу без встановленого пароля: {login_res}")

    print("Журнал аудиту")
    for entry in noname_account.audit_log.entries:
        ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Використай правильну команду!!!")