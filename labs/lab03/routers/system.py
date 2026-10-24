from fastapi import APIRouter

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT

router = APIRouter(tags=["System"])


@router.get("/ping", summary="Перевірка доступності API")
def ping():
    return {"status": "ok"}


@router.get("/student", summary="Дані про студента")
def get_student():
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT,
    }