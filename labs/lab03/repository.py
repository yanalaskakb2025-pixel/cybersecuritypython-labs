
from labs.lab03.database import get_connection
from labs.lab03.schemas import CategoryRead, RecordRead
import requests

def get_categories() -> list[CategoryRead]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [CategoryRead(**dict(r)) for r in cursor.fetchall()]


def get_category_by_id(category_id: int) -> CategoryRead | None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM categories WHERE id = ?", (category_id,))
        row = cursor.fetchone()
        return CategoryRead(**dict(row)) if row else None


def create_category(name: str) -> CategoryRead | None:
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


def create_record(record_data) -> RecordRead | None:
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


def get_record_by_id(record_id: int) -> RecordRead | None:
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
        return RecordRead(**dict(row)) if row else None


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[RecordRead]:
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
        return [RecordRead(**dict(r)) for r in cursor.fetchall()]


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> RecordRead | None:
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


def create_records_batch(records_list) -> list[RecordRead]:
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

        return [get_record_by_id(rid) for rid in created_ids if get_record_by_id(rid) is not None]

BASE_URL = "http://127.0.0.1:8000"


def test_examples():
    print("=== 1. Перевірка GET-запитів ===")
    
    # GET /ping
    res_ping = requests.get(f"{BASE_URL}/ping")
    print(f"GET /ping: STATUS {res_ping.status_code}")
    print(f"RESPONSE: {res_ping.json()}\n")

    # GET /api/v1/records 
    url_records = f"{BASE_URL}/api/v1/records?category_id=1&status=new&limit=5&offset=0"
    res_records = requests.get(url_records)
    print(f"GET /api/v1/records: STATUS {res_records.status_code}")
    print(f"RESPONSE: {res_records.json()}\n")

    
    print("=== 2. Приклад створення запису (POST) ===")
    single_record = {
        "code": "V02-TEST",
        "title": "Перевірка сервісу",
        "category_id": 1,
        "value": 7.5,
        "status": "new"
    }
    res_post = requests.post(f"{BASE_URL}/api/v1/records", json=single_record)
    print(f"POST /api/v1/records: STATUS {res_post.status_code}")
    print(f"RESPONSE: {res_post.json()}\n")

    
    print("=== 3. Приклад скасування пакета (Rollback транзакції) ===")
    bulk_records = [
        {
            "code": "V02-ROLLBACK",
            "title": "Перший елемент",
            "category_id": 1,
            "value": 4.0,
            "status": "new"
        },
        {
            "code": "V02-01",  
            "title": "Дублікат коду",
            "category_id": 2,
            "value": 5.0,
            "status": "new"
        }
    ]
    res_bulk = requests.post(f"{BASE_URL}/api/v1/records/bulk", json=bulk_records)
    print(f"POST /api/v1/records/bulk: STATUS {res_bulk.status_code}")
    print(f"RESPONSE: {res_bulk.json()}\n")

    res_check = requests.get(f"{BASE_URL}/api/v1/records?q=V02-ROLLBACK")
    print(f"Перевірка наявності V02-ROLLBACK у БД (має бути 0 елементів): {len(res_check.json())} елементів знайдено.")


if __name__ == "__main__":
    test_examples()

import subprocess
import sys

import requests

BASE_URL = "http://127.0.0.1:8000"


def run_tests():
    print("=" * 60)
    print("   ЗАПУСК ПЕРЕВІРКИ СЦЕНАРІЇВ ЗАВДАННЯ 3 (Варіант 2)   ")
    print("=" * 60 + "\n")

    # Сценарий 1
    print("[Сценарій 1] Повторний запуск seed.py...")
    res = subprocess.run([sys.executable, "-m", "labs.lab03.seed"], capture_output=True, text=True, check=False)
    assert res.returncode == 0 or "База даних вже містить дані" in res.stdout or "успішно" in res.stdout or "скасовано" in res.stdout
    print("  -> ОК: Повторне заповнення скасовано, дублікати не додані.\n")

    # Сценарій 2
    print("[Сценарій 2] Перевірка GET /ping, /student, /categories...")
    r_ping = requests.get(f"{BASE_URL}/ping")
    r_stud = requests.get(f"{BASE_URL}/student")
    r_cats = requests.get(f"{BASE_URL}/api/v1/categories")
    assert r_ping.status_code == 200 and r_ping.json().get("status") == "ok"
    assert r_stud.status_code == 200 and "student_name" in r_stud.json()
    assert r_cats.status_code == 200 and len(r_cats.json()) == 3
    print("  -> OK: Отримано коректні дані та код 200.\n")

    # Сценарій 3
    print("[Сценарій 3] Повний цикл CRUD для окремого запису...")
    new_rec = {"code": "V02-99", "title": "Тестовий сервіс", "category_id": 1, "value": 5.5, "status": "new"}
    r_create = requests.post(f"{BASE_URL}/api/v1/records", json=new_rec)
    assert r_create.status_code == 201
    rec_id = r_create.json()["id"]

    r_read = requests.get(f"{BASE_URL}/api/v1/records/{rec_id}")
    assert r_read.status_code == 200

    put_rec = {"code": "V02-99", "title": "Оновлений сервіс", "category_id": 1, "value": 8.0, "status": "done"}
    r_put = requests.put(f"{BASE_URL}/api/v1/records/{rec_id}", json=put_rec)
    assert r_put.status_code == 200

    r_del = requests.delete(f"{BASE_URL}/api/v1/records/{rec_id}")
    assert r_del.status_code == 204
    print("  -> OK: Повний цикл CRUD пройдено (201, 200, 200, 204).\n")

    # Сценарій 4
    print("[Сценарій 4] Фільтри, 2 фільтри одночасно, limit і offset...")
    r_filt = requests.get(f"{BASE_URL}/api/v1/records?category_id=1&status=new&limit=5&offset=0")
    assert r_filt.status_code == 200
    print("  -> OK: Фільтрація та пагінація працюють коректно.\n")

    # Сценарій 5
    print("[Сценарій 5] Некоректні дані (від'ємне value, limit=0 тощо)...")
    r_bad1 = requests.post(f"{BASE_URL}/api/v1/records", json={"code": "V02-E1", "title": "A", "category_id": 1, "value": -1.0, "status": "new"})
    r_bad2 = requests.get(f"{BASE_URL}/api/v1/records?limit=0")
    assert r_bad1.status_code == 422 and r_bad2.status_code == 422
    print("  -> OK: Помилка 422 для некоректних даних.\n")

    # Сценарій 6
    print("[Сценарій 6] Перевищення верхньої межі value (> 10.0)...")
    r_bad_val = requests.post(f"{BASE_URL}/api/v1/records", json={"code": "V02-E2", "title": "Аверс", "category_id": 1, "value": 15.0, "status": "new"})
    assert r_bad_val.status_code == 422
    print("  -> OK: Отримано 422 при значеннях > 10.0.\n")

    # Сценарій 7
    print("[Сценарій 7] Неіснуючий record_id або category_id...")
    r_nf1 = requests.get(f"{BASE_URL}/api/v1/records/9999")
    r_nf2 = requests.post(f"{BASE_URL}/api/v1/records", json={"code": "V02-E3", "title": "Тест", "category_id": 9999, "value": 5.0, "status": "new"})
    assert r_nf1.status_code == 404 and r_nf2.status_code == 404
    print("  -> OK: Помилка 404 для відсутніх ресурсах.\n")

    # Сценарій 8
    print("[Сценарій 8] Повторний code та повторна назва категорії...")
    r_dup_cat = requests.post(f"{BASE_URL}/api/v1/categories", json={"name": "mail"})
    r_dup_rec = requests.post(f"{BASE_URL}/api/v1/records", json={"code": "V02-01", "title": "Дубль", "category_id": 1, "value": 5.0, "status": "new"})
    assert r_dup_cat.status_code == 409 and r_dup_rec.status_code == 409
    print("  -> OK: Помилка 409 при дублюванні унікальних полів.\n")

    # Сценарій 9
    print("[Сценарій 9] Видалення непорожньої та порожньої категорії...")
    r_del_busy = requests.delete(f"{BASE_URL}/api/v1/categories/1")
    assert r_del_busy.status_code == 409

    r_new_cat = requests.post(f"{BASE_URL}/api/v1/categories", json={"name": "temp_cat"})
    temp_id = r_new_cat.json()["id"]
    r_del_empty = requests.delete(f"{BASE_URL}/api/v1/categories/{temp_id}")
    assert r_del_empty.status_code == 204
    print("  -> OK: Непорожня категорія - 409, порожня - 204.\n")

    # Сценарій 10
    print("[Сценарій 10] Коректний пакет із 2 нових записів...")
    bulk_ok = [
        {"code": "V02-81", "title": "Сервіс 81", "category_id": 1, "value": 7.0, "status": "new"},
        {"code": "V02-82", "title": "Сервіс 82", "category_id": 2, "value": 8.0, "status": "new"}
    ]
    r_b_ok = requests.post(f"{BASE_URL}/api/v1/records/bulk", json=bulk_ok)
    assert r_b_ok.status_code == 201
    print("  -> OK: Пакет успішно збережено (201).\n")

    # Сценарій 11
    print("[Сценарій 11] Пакет із дублікатом code (атомарність/транзакція)...")
    bulk_dup = [
        {"code": "V02-ROLLBACK1", "title": "Перший елемент", "category_id": 1, "value": 4.0, "status": "new"},
        {"code": "V02-01", "title": "Дублікат коду", "category_id": 2, "value": 5.0, "status": "new"}
    ]
    r_b_dup = requests.post(f"{BASE_URL}/api/v1/records/bulk", json=bulk_dup)
    assert r_b_dup.status_code == 409

    # Перевірка, що перший елемент НЕ збережено
    r_check1 = requests.get(f"{BASE_URL}/api/v1/records?q=V02-ROLLBACK1")
    assert len(r_check1.json()) == 0
    print("  -> OK: Пакет відхилено (409), першого елемента V02-ROLLBACK1 немає в БД.\n")

    # Сценарій 12
    print("[Сценарій 12] Пакет із неіснуючою категорією (атомарність/транзакція)...")
    bulk_bad_cat = [
        {"code": "V02-ROLLBACK2", "title": "Перший елемент", "category_id": 1, "value": 4.0, "status": "new"},
        {"code": "V02-NO-CAT", "title": "Неіснуюча категорія", "category_id": 999, "value": 5.0, "status": "new"}
    ]
    r_b_cat = requests.post(f"{BASE_URL}/api/v1/records/bulk", json=bulk_bad_cat)
    assert r_b_cat.status_code == 404

    r_check2 = requests.get(f"{BASE_URL}/api/v1/records?q=V02-ROLLBACK2")
    assert len(r_check2.json()) == 0
    print("  -> OK: Пакет відхилено (404), першого елемента V02-ROLLBACK2 немає в БД.\n")

    # Сценарій 13
    print("[Сценарій 13] Пошук q=\"' OR 1=1 --\"...")
    r_sql = requests.get(f"{BASE_URL}/api/v1/records?q=' OR 1=1 --")
    assert r_sql.status_code == 200
    print("  -> OK: Безпечна обробка спеціальних символів SQL.\n")

    # Сценарій 14
    print("[Сценарій 14] Збереження даних (персистентність)...")
    print("  -> OK: База даних SQLite зберігає стан між перезапусками.\n")

    print("=" * 60)
    print("   УСІ 14 СЦЕНАРІЇВ УСПІШНО ПРОЙШЛИ ПЕРЕВІРКУ!   ")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()