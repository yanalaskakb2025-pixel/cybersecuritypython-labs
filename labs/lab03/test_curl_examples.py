import requests

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