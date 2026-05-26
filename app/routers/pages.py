from fastapi import APIRouter
from starlette.responses import FileResponse

from app.config import BASE_DIR


router = APIRouter()


@router.get("/")
def root() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
