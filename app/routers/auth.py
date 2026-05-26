from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.dependencies import CurrentUser, DbSession, bearer_scheme
from app.models import RoleName, SessionToken, User, UserRole
from app.schemas import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from app.security import create_token, decode_token, hash_password, utc_now, verify_password
from app.services import find_role, serialize_user


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, db: DbSession) -> UserResponse:
    if db.scalar(select(User).where(User.email == data.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    user = User(
        full_name=data.full_name,
        email=data.email,
        password_hash=hash_password(data.password),
        is_active=True,
        created_at=utc_now(),
    )
    db.add(user)
    try:
        db.flush()
        db.add(UserRole(user_id=user.id, role_id=find_role(db, RoleName.user.value).id))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    return serialize_user(db, user)


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: DbSession) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == data.email))
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(access_token=create_token(db, user.id), user=serialize_user(db, user))


@router.post("/logout")
def logout(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    current_user: CurrentUser,
    db: DbSession,
) -> dict[str, str]:
    token = db.get(SessionToken, decode_token(credentials.credentials)["jti"])
    token.revoked = True
    db.commit()
    return {"message": "Logged out"}
