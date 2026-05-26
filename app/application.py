from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import BASE_DIR
from app.routers import admin, auth, orders, pages, users
from app.services import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="T3 Authentication and Authorization API",
        description="Custom JWT authentication and role-based access control demo.",
        lifespan=lifespan,
    )
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    application.include_router(pages.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(orders.router)
    application.include_router(admin.router)
    return application


app = create_app()
