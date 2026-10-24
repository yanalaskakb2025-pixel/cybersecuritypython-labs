import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "lab3.sqlite3"


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    # Автоматична перевірка та ініціалізація таблиць за методичкою
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY CHECK (id > 0),
            name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) BETWEEN 2 AND 40)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY CHECK (id > 0),
            code TEXT NOT NULL UNIQUE CHECK (length(trim(code)) BETWEEN 3 AND 40),
            title TEXT NOT NULL CHECK (length(trim(title)) BETWEEN 3 AND 120),
            category_id INTEGER NOT NULL CHECK (typeof(category_id) = 'integer' AND category_id > 0),
            value REAL NOT NULL CHECK (typeof(value) IN ('integer', 'real') AND value BETWEEN 0 AND 10),
            status TEXT NOT NULL CHECK (status IN ('new', 'in_progress', 'done')),
            FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE RESTRICT
        )
        """
    )
    # Авто-додавання категорій 2 варіанта, якщо вони відсутні
    cursor.execute("SELECT COUNT(*) FROM categories")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(1, "mail"), (2, "vpn"), (3, "dns")],
        )
    conn.commit()
    return conn


def get_categories() -> list[dict]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]


def get_category_by_id(category_id: int) -> dict | None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM categories WHERE id = ?", (category_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def create_category(name: str) -> dict:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
        conn.commit()
        cat_id = cursor.lastrowid
    return get_category_by_id(cat_id)


def delete_category(category_id: int) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        return cursor.rowcount > 0


def create_record(record_data) -> dict:
    data = record_data.model_dump() if hasattr(record_data, "model_dump") else dict(record_data)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO records (code, title, category_id, value, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (data["code"], data["title"], data["category_id"], data["value"], data["status"]),
        )
        conn.commit()
        record_id = cursor.lastrowid
    return get_record_by_id(record_id)


def get_record_by_id(record_id: int) -> dict | None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, c.name as category_name, r.value, r.status
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    with get_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT r.id, r.code, r.title, r.category_id, c.name as category_name, r.value, r.status
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE 1=1
        """
        params = []
        if category_id:
            query += " AND r.category_id = ?"
            params.append(category_id)
        if status:
            query += " AND r.status = ?"
            params.append(status)
        if min_value is not None:
            query += " AND r.value >= ?"
            params.append(min_value)
        if q:
            query += " AND instr(r.title, ?) > 0"
            params.append(q)

        query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def update_record(record_id: int, code: str, title: str, category_id: int, value: float, status: str) -> dict | None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE records
            SET code = ?, title = ?, category_id = ?, value = ?, status = ?
            WHERE id = ?
            """,
            (code, title, category_id, value, status, record_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return None
    return get_record_by_id(record_id)


def delete_record(record_id: int) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM records WHERE id = ?", (record_id,))
        conn.commit()
        return cursor.rowcount > 0


def create_records_batch(records_list) -> list[dict]:
    with get_connection() as conn:
        cursor = conn.cursor()
        created_ids = []
        for r in records_list:
            data = r.model_dump() if hasattr(r, "model_dump") else dict(r)
            cursor.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (data["code"], data["title"], data["category_id"], data["value"], data["status"]),
            )
            created_ids.append(cursor.lastrowid)
        conn.commit()

    return [get_record_by_id(rid) for rid in created_ids]