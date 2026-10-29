from typing import Literal
# Pydantic перевіряє типи даних, наявність обов полів, правила обмежень і діапазони, автоматичне перетв типів даних
from pydantic import BaseModel, ConfigDict, Field

# 1 питання Сутності категорії і записи
class CategoryBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=2, max_length=40) # Pydantic перевіряє, щоб назва категорії мала від 2 до 40 символів


class CategoryCreate(CategoryBase):  # Зберігає довідник категорій для систематизації даних
    pass


class CategoryRead(CategoryBase):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore", from_attributes=True)
    id: int = Field(gt=0)

# Зберігає основні дані системи
class RecordCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120) # Перевіряються на довжину від 3 до 40 та від 3 до 120 символів
    category_id: int = Field(gt=0)
    value: float = Field(ge=0.0, le=10.0, allow_inf_nan=False)
    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    pass


class RecordRead(RecordCreate):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore", from_attributes=True)
    id: int = Field(gt=0)
    category_name: str