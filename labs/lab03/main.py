from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records, system


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Реєстр вразливостей мережевих сервісів",
    description="Сервіс обліку результатів навчальної перевірки мережевих сервісів. Одиниця вимірювання (unit): score (Оцінка небезпеки вразливості від 0.0 до 10.0).",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/docs")


app.include_router(system.router)
app.include_router(categories.router)
app.include_router(records.router)