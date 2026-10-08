import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

PBKDF2_ITERATIONS = 100_000  # Кількість ітерацій хешування для уповільнення брутфорсу
SALT_SIZE_BYTES = 16  # Розмір солі
SESSION_TIMEOUT_SEC = 900  # 15 хв
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"  # Який може бути емейл
)


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",  # По дефолту юзер
        password: str | None = None,
        active: bool = True,
    ) -> None:
        if not username or not username.strip():  # Перевірка чи не порожнє
            raise ValueError("Ім'я користувача не може бути порожнім.")
        self.username: str = username.strip()
        self.email: str = email
        self.role: str = role
        self.active: bool = active
        self._password_salt: bytes = b""  # Приховане поле солі, ці поля є внутрішні
        self._password_hash: bytes = b""  # Приховане поле хешу ІНкапсуляція

        if password is not None:
            self.set_password(password)

    @property  # Інкапсуляяція
    def email(self) -> str:
        return self._email

    @email.setter  # Перевіряє правильність формату пошти Інкапсуляція
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str | None) -> None:
        """Встановлює хеш пароля та сіль"""
        if not password:
            self._password_salt = b""
            self._password_hash = b""
            return

        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має бути рядком довжиною щонайменше 4 символи.")

        self._password_salt = os.urandom(SALT_SIZE_BYTES)
        self._password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self._password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою безпечного порівняння hmac.compare_digest"""
        if not self._password_hash or not self._password_salt:
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self._password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self._password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача"""
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status={status})"
        )


class Admin(User):  # Наслідування
    """Клас адміністратора, що наслідує User та додає управління правами доступу"""

    def __init__(  # Ініціалізація
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(
            username=username,
            email=email,
            role="admin",
            password=password,
            active=active,
        )
        self.permissions: set[str] = (
            set(permissions)
            if permissions is not None
            else set()  # Перетворюємо у множину бо у ній немає дублікатів
        )

    def grant_permission(self, permission: str) -> None:  # Додає права адміну
        """Надає право доступу адміністратору"""
        if not permission or not permission.strip():
            raise ValueError("Назва дозволу не може бути порожньою.")
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:  # Скасування права
        """Відкликає право доступу адміністратора"""
        self.permissions.discard(permission.strip())

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність вказаного дозволу"""
        return permission.strip() in self.permissions

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        perms = (
            ", ".join(sorted(self.permissions)) if self.permissions else "none"
        )  # Форматування і сортув прав
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"status={status}, permissions=[{perms}])"
        )


class Session:
    """Клас користувацької сесії з контролем часу активності"""

    def __init__(self, ip: str) -> None:
        if not ip or not ip.strip():
            raise ValueError("IP-адреса сесії не може бути порожньою.")
        now = datetime.now(timezone.utc)
        self.ip: str = ip.strip()
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:  # Оовлює last_activity
        """Оновлює час останньої активності сесії поточним часом"""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут з моменту останньої активності"""
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії має бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(
            seconds=timeout_sec
        )  # Обчислення таймауту

    def __str__(self) -> str:  # Форматування
        return (
            f"Session(ip='{self.ip}', login_time='{self.login_time.isoformat()}', "
            f"last_activity='{self.last_activity.isoformat()}')"
        )


@dataclass(frozen=True)  # Захист від змін, але не є чистим прикладом інкапсуляції
class AuditEntry:
    """Запис у журнал аудиту"""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій безпеки"""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        """Повертає копію списку записів аудиту"""
        return list(self._entries)

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис із поточним часом"""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> None:
        """Виводить усі записи журналу аудиту"""
        print("--Записи журналу аудиту--")
        if not self._entries:
            print("(Журнал порожній)")
            return
        for entry in self._entries:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")


class UserAccount:
    """Обліковий запис, який об'єднує User, Session та AuditLog (композиція)"""

    _ALLOWED_KEYS: ClassVar[dict[str, type | tuple[type, ...]]] = {
        "user": User,
        "session": (Session, type(None)),
        "audit_log": AuditLog,
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("Поле 'user' має бути екземпляром класу User.")
        if session is not None and not isinstance(session, Session):
            raise TypeError("Поле 'session' має бути екземпляром Session або None.")
        if audit_log is not None and not isinstance(audit_log, AuditLog):
            raise TypeError("Поле 'audit_log' має бути екземпляром AuditLog.")

        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Спроба зайти в систему"""
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(self.user.username, "login_success")
        return True

    def is_authenticated(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевірка наявності активної сесії без продовження"""
        if self.session is None or not self.user.active:
            return False
        return self.session.is_active(timeout_sec)

    def logout(self) -> None:
        """Завершує поточну сесію та фіксує вихід у журналі аудиту."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        expected_type = self._ALLOWED_KEYS[key]
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Неправильний тип для ключа '{key}': отримано {type(value).__name__}."
            )
        setattr(self, key, value)
