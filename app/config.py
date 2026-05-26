import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.validators import validate_password


load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseModel):
    database_url: str = Field(min_length=1)
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = Field(default="HS256", pattern=r"^HS(256|384|512)$")
    token_expire_minutes: int = Field(default=480, ge=5, le=10080)
    seed_data: bool = True
    admin_email: EmailStr
    admin_password: str
    manager_email: EmailStr
    manager_password: str
    user_email: EmailStr
    user_password: str

    @field_validator("admin_password", "manager_password", "user_password")
    @classmethod
    def validate_seed_password(cls, value: str) -> str:
        return validate_password(value)


def read_settings() -> Settings:
    required = (
        "DATABASE_URL",
        "JWT_SECRET",
        "ADMIN_EMAIL",
        "ADMIN_PASSWORD",
        "MANAGER_EMAIL",
        "MANAGER_PASSWORD",
        "USER_EMAIL",
        "USER_PASSWORD",
    )
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError(f"Missing environment values: {', '.join(missing)}")
    return Settings(
        database_url=os.environ["DATABASE_URL"],
        jwt_secret=os.environ["JWT_SECRET"],
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        token_expire_minutes=os.getenv("TOKEN_EXPIRE_MINUTES", "480"),
        seed_data=os.getenv("SEED_DATA", "true").lower() == "true",
        admin_email=os.environ["ADMIN_EMAIL"],
        admin_password=os.environ["ADMIN_PASSWORD"],
        manager_email=os.environ["MANAGER_EMAIL"],
        manager_password=os.environ["MANAGER_PASSWORD"],
        user_email=os.environ["USER_EMAIL"],
        user_password=os.environ["USER_PASSWORD"],
    )


settings = read_settings()
