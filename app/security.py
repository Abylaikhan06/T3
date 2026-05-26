from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt
import jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.models import SessionToken


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_token(db: Session, user_id: int) -> str:
    token_id = str(uuid4())
    expires_at = utc_now() + timedelta(minutes=settings.token_expire_minutes)
    token = jwt.encode(
        {"sub": str(user_id), "jti": token_id, "exp": expires_at},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    db.add(SessionToken(token_id=token_id, user_id=user_id, expires_at=expires_at, revoked=False))
    db.commit()
    return token


def decode_token(value: str) -> dict:
    return jwt.decode(value, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
