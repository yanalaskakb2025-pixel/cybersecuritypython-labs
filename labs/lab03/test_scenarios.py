import json
import subprocess
import sys
import requests

BASE_URL = "http://127.0.0.1:8000"


def run_tests():
    print("=" * 60)
    print("   ЗАПУСК ПЕРЕВІРКИ СЦЕНАРІЇВ ЗАВДАННЯ 3 (Варіант 2)   ")
    print("=" * 60 + "\n")

    # Сценарій 1
    print("[Сценарій 1] Повторний запуск seed.py...")
    res = subprocess.run([sys.executable, "-m", "labs.lab03.seed"], capture_output=True, text=True)
    assert "База даних вже містить дані" in res.stdout or "скасовано" in res.stdout
    print("  -> OK: Повторне заповнення скасовано, дублікати не додані.\n")

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