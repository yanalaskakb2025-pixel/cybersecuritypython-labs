import sqlite3

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository, schemas

router = APIRouter(prefix="/api/v1/categories", tags=["Categories"])


@router.get("", response_model=list[schemas.CategoryRead], summary="Get Categories")
def get_categories():
    return repository.get_categories()


@router.get("/{category_id}", response_model=schemas.CategoryRead, summary="Get Category")
def get_category(category_id: int = Path(..., gt=0)):
    cat = repository.get_category_by_id(category_id)
    if not cat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Категорію не знайдено."
        )
    return cat


@router.post("", response_model=schemas.CategoryRead, status_code=status.HTTP_201_CREATED, summary="Create Category")
def create_category(category: schemas.CategoryCreate):
    try:
        return repository.create_category(category.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія з такою назвою вже існує."
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete Category")
def delete_category(category_id: int = Path(..., gt=0)):
    if not repository.get_category_by_id(category_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Категорію не знайдено."
        )
    try:
        deleted = repository.delete_category(category_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Неможливо видалити категорію, що містить записи."
            )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Неможливо видалити категорію, що містить записи."
        )