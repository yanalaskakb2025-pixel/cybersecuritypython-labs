import argparse
import datetime
import hashlib
import json
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass  # Автоматично створює конструктор __init__ для класу
class FileMetadata:  # Клас для збереження атрибутів кожного окремого файла
    path: str  # Шлях до файла
    sha256: str  # Хеш
    size: int  # Розмір файла
    mtime: str  # Час остан зміни файла


def compute_sha256(
    file_path: Path,
) -> str:  # Функція розрахунку хешу для заданого шляху
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(
                lambda: f.read(4096), b""
            ):  # Файл зчитується частинами
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except OSError as e:
        logger.error(f"Не вдалося прочитати файл {file_path}: {e}")
        return "Щось пішло не так"


# Рекурсивне сканування директорії
def scan_directory(
    target_dir: Path,
) -> dict[str, FileMetadata]:  # Скан директ і повернення словника об'є метаданих
    records: dict[str, FileMetadata] = {}  # Результати
    if not target_dir.exists() or not target_dir.is_dir():  # Чи існує папка
        return records

    for path_obj in target_dir.rglob("*"):  # Обхід папок
        if path_obj.is_file():  # Обробка тільки файлів
            try:
                rel_path = path_obj.relative_to(target_dir).as_posix()
                stat = path_obj.stat()  # Інформація про файл розм і час
                mtime_iso = datetime.datetime.fromtimestamp(
                    stat.st_mtime, tz=datetime.timezone.utc
                ).isoformat()
                file_hash = compute_sha256(path_obj)

                records[rel_path] = FileMetadata(  # Збереж у словник
                    path=rel_path,
                    sha256=file_hash,
                    size=stat.st_size,
                    mtime=mtime_iso,
                )
            except OSError as e:
                logger.warning(f"Помилка обробки {path_obj}: {e}")

    return records


# Режим generate : створення еталонного контрольного файлу baseline.json .
def mode_generate(target_dir: Path, baseline_path: Path) -> None:  # Створення еталонного контрольного файлу baseline.json
    if not target_dir.exists():
        print(f"[ERROR] Target directory does not exist: {target_dir}")  # Чи є папка
        sys.exit(1)

    print(f"[INFO] Scanning directory: {target_dir.as_posix()}")
    scanned_data = scan_directory(target_dir)

    baseline_json = [
        asdict(metadata) for metadata in scanned_data.values()
    ]  # Перетв в словник

    baseline_path.parent.mkdir(parents=True, exist_ok=True)  # Ств папок для файлу
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_json, f, indent=4, ensure_ascii=False)

    print(f"[INFO] Baseline successfully generated at {baseline_path.as_posix()}")


# Режим check : порівняння поточного стану з baseline.json та виявлення створених, видалених або модифікованих файлів.
def mode_check(
    target_dir: Path, baseline_path: Path, log_file: Path | None
) -> None:  # Перевірка цілісності файла
    if not baseline_path.exists():
        print(f"[ERROR] Baseline file not found: {baseline_path.resolve()}")
        sys.exit(1)

    if not target_dir.exists():
        print(f"[ERROR] Directory not found: {target_dir.resolve()}")
        sys.exit(1)

    base_str = baseline_path.as_posix()  # Нормалізац виводу
    dir_str = target_dir.as_posix()
    if not dir_str.endswith("/"):
        dir_str += "/"

    print(f"[INFO] Loading baseline file: {base_str}")
    logger.info(f"Loading baseline file: {base_str}")

    with open(baseline_path, "r", encoding="utf-8") as f:
        raw_baseline = json.load(f)

    baseline_data: dict[str, dict] = {}  # Читає не залежно чи був списком чи словником
    if isinstance(raw_baseline, list):
        for item in raw_baseline:
            rel_path = item["path"].replace("\\", "/")
            baseline_data[rel_path] = item
    elif isinstance(raw_baseline, dict):
        for k, v in raw_baseline.items():
            rel_path = k.replace("\\", "/")
            if isinstance(v, dict):
                baseline_data[rel_path] = v

    print(f"[INFO] Scanning directory: {dir_str}")
    logger.info(f"Scanning directory: {dir_str}")
    current_data = scan_directory(target_dir)

    baseline_keys = set(baseline_data.keys())  # Множини шляхів
    current_keys = set(current_data.keys())

    unchanged = []  # Незмін дані
    modified = []  # Модифіковані дані
    created = sorted(current_keys - baseline_keys)  # Знаход створ файли
    deleted = sorted(baseline_keys - current_keys)  # Видалені

    for path in sorted(current_keys & baseline_keys):  # Перевірка спільних файлів
        if current_data[path].sha256 == baseline_data[path]["sha256"]:
            unchanged.append(path)
        else:
            modified.append(path)

    total_monitored = len(baseline_keys)  # К-сть зафіксованих фвфайлів

    print("\n_-_ File integrity inspection summary _-_")
    print(f"Total monitored files : {total_monitored}")
    print(f"Unchanged files       : {len(unchanged)}")
    print(f"Modified files        : {len(modified)}")
    print(f"Created files         : {len(created)}")
    print(f"Deleted files         : {len(deleted)}")

    anomalies_found = bool(modified or created or deleted)

    if anomalies_found:
        print("\n_-_ Detected Anomalies -_-\n")

        for path in modified:
            exp_hash = baseline_data[path]["sha256"]  # Який повинен бути
            act_hash = current_data[path].sha256  # Який є
            full_path = (target_dir / path).as_posix()

            print(f"[MODIFIED] {full_path}")
            print("  Expected SHA-256 : ")
            print(f"  {exp_hash}")
            print("  Actual SHA-256   : ")
            print(f"  {act_hash}")
            # Фіксація тривожних подій у лог-файлі через logging.warning .
            logger.warning(
                f"[MODIFIED] {full_path} | Expected: {exp_hash} | Actual: {act_hash}"  # Фіксація факту модифікації
            )

        for path in created:
            file_info = current_data[path]  # Витяг метаданих для нового файла
            full_path = (target_dir / path).as_posix()  # Формування шляху до файлу
            print(f"[CREATED] {full_path} (Size: {file_info.size} B)")
            logger.warning(
                f"[CREATED] {full_path} | Size: {file_info.size} B | SHA: {file_info.sha256}"  # Фіксац створ файлу
            )

        for path in deleted:  # Які були в baseline.json але зникли з дискa
            full_path = (target_dir / path).as_posix()
            print(f"[DELETED] {full_path}")
            logger.warning(f"[DELETED] {full_path}")  # Фікс видалених

        log_path_str = (
            log_file.as_posix() if log_file else "labs/lab02/data/fim_audit.log"
        )  # Підсумок і шлях долог файлу
        print(
            f"\n[WARNING] Security alerts detected! Check audit log at {log_path_str}"
        )
        logger.warning(f"Security alerts detected! Check audit log at {log_path_str}")
    else:
        print("\n[INFO] All files are intact. No changes detected.")


def setup_logging(log_file_path: Path | None) -> None:
    if log_file_path:
        log_file_path.parent.mkdir(
            parents=True, exist_ok=True
        )  # Ств директорії для логу
        logging.basicConfig(
            level=logging.INFO,  # Рівні подій для запису
            format="%(asctime)s [%(levelname)s] %(message)s",
            filename=str(log_file_path),  # Шлях до запису
            filemode="a",  # Нові записи в кінець
            encoding="utf-8",
            force=True,
        )


def main() -> None:  # Парсер для виведення у консоль для CLI
    parser = argparse.ArgumentParser(
        description="FIM - File Integrity Monitor"
    )  # Перетворення у зручний формат для обробки
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--mode", choices=["generate", "check"], required=True)
    parser.add_argument("--log-file", type=Path, default=None)

    args = parser.parse_args()

    setup_logging(args.log_file)

    if args.mode == "generate":
        mode_generate(args.dir, args.baseline)
    elif args.mode == "check":
        mode_check(
            args.dir, args.baseline, args.log_file
        )  # Команда для вводу  python -m labs.lab02.task2 --dir labs/lab02/data/data_v02/monitored --baseline labs/lab02/data/data_v02/baseline.json --mode check --log-file labs/lab02/data/fim_audit.log


if __name__ == "__main__":
    main()