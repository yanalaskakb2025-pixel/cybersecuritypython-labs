import sqlite3
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository, schemas
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/api/v1/records", tags=["Records"])


@router.post("", response_model=schemas.RecordRead, status_code=status.HTTP_201_CREATED, summary="Create Record")
def create_record(record: schemas.RecordCreate):
    if not repository.get_category_by_id(record.category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Вказану категорію не знайдено.",
        )
    try:
        return repository.create_record(record)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Запис із таким кодом (code) вже існує.",
        )


@router.get("", response_model=list[RecordRead], summary="Список із фільтрами")
def get_records(
    category_id: int | None = Query(None, gt=0),
    status_val: str | None = Query(None, alias="status"),
    min_value: float | None = Query(None, ge=0.0, le=10.0),
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return repository.get_records(
        category_id=category_id,
        status=status_val,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead, summary="Один запис")
def get_record(record_id: int = Path(..., gt=0)):
    record = repository.get_record_by_id(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис із таким ID не знайдено.",
        )
    return record


@router.put("/{record_id}", response_model=RecordRead, summary="Повна заміна змінюваних полів")
def update_record(
    record_id: int = Path(..., gt=0),
    record: RecordReplace = Body(...), # noqa: B008
):
    if not repository.get_category_by_id(record.category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Вказану категорію не знайдено.",
        )
    try:
        updated = repository.update_record(
            record_id=record_id,
            code=record.code,
            title=record.title,
            category_id=record.category_id,
            value=record.value,
            status=record.status,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Запис із таким ID не знайдено.",
            )
        return updated
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Конфлікт коду запису.",
        )


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Видалення запису")
def delete_record(record_id: int = Path(..., gt=0)):
    deleted = repository.delete_record(record_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запис із таким ID не знайдено.",
        )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення з атомарним контролем",
)
def create_records_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
):
    codes = [r.code for r in records]
    if len(codes) != len(set(codes)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Пакет містить дублікати коду (code).",
        )

    for r in records:
        if not repository.get_category_by_id(r.category_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Категорію з ID {r.category_id} не знайдено.",
            )

    try:
        return repository.create_records_batch(records)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Дублікат коду у базі даних.",
        )