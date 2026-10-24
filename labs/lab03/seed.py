import json
import sqlite3
from pathlib import Path

from labs.lab03.database import get_connection


def seed_database():
    seed_path = Path(__file__).parent / "data" / "seed.json"

    if not seed_path.exists():
        print(f"Файл {seed_path} не знайдено!")
        return

    with open(seed_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM records;")
        cursor.execute("DELETE FROM categories;")

        for cat in data.get("categories", []):
            cursor.execute(
                "INSERT INTO categories (id, name) VALUES (?, ?);",
                (cat["id"], cat["name"]),
            )

        for rec in data.get("records", []):
            cursor.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    rec["code"],
                    rec["title"],
                    rec["category_id"],
                    rec["value"],
                    rec["status"],
                ),
            )

        conn.commit()
        print("Базу даних успішно заповнено правильними даними з seed.json!")
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Помилка бази даних під час заповнення: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed_database()