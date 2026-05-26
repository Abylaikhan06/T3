from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.dependencies import CurrentUser, DbSession
from app.models import SessionToken, User
from app.schemas import ProfileUpdateRequest, UserResponse
from app.services import serialize_user


router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
def get_profile(current_user: CurrentUser, db: DbSession) -> UserResponse:
    return serialize_user(db, current_user)


@router.put("/me", response_model=UserResponse)
def update_profile(data: ProfileUpdateRequest, current_user: CurrentUser, db: DbSession) -> UserResponse:
    if data.email and data.email != current_user.email:
        if db.scalar(select(User).where(User.email == data.email)):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
        current_user.email = data.email
    if data.full_name:
        current_user.full_name = data.full_name
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    return serialize_user(db, current_user)


@router.delete("/me")
def delete_profile(current_user: CurrentUser, db: DbSession) -> dict[str, str]:
    current_user.is_active = False
    tokens = db.scalars(select(SessionToken).where(SessionToken.user_id == current_user.id)).all()
    for token in tokens:
        token.revoked = True
    db.commit()
    return {"message": "Account deactivated and sessions closed"}
