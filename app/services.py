from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import AccessRoleRule, BusinessElement, ElementName, Role, RoleName, User, UserRole
from app.schemas import UserResponse
from app.security import hash_password, utc_now


PERMISSIONS = (
    "read_permission",
    "read_all_permission",
    "create_permission",
    "update_permission",
    "update_all_permission",
    "delete_permission",
    "delete_all_permission",
)

MOCK_ORDERS = [
    {"id": 1, "title": "Laptop order", "amount": Decimal("1500.00"), "owner_email": str(settings.user_email).lower()},
    {"id": 2, "title": "Office supplies", "amount": Decimal("250.00"), "owner_email": str(settings.manager_email).lower()},
]


def find_role(db: Session, name: str) -> Role:
    return db.scalar(select(Role).where(Role.name == name))


def find_element(db: Session, name: str) -> BusinessElement:
    return db.scalar(select(BusinessElement).where(BusinessElement.name == name))


def seed_user(db: Session, full_name: str, email: str, password: str, role_name: str) -> None:
    if db.scalar(select(User).where(User.email == email)):
        return
    user = User(
        full_name=full_name,
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        created_at=utc_now(),
    )
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=find_role(db, role_name).id))


def seed_rules(db: Session) -> None:
    values = {
        ("admin", "orders"): (True, True, True, True, True, True, True),
        ("admin", "access_rules"): (True, True, True, True, True, True, True),
        ("manager", "orders"): (True, True, True, True, True, False, False),
        ("manager", "access_rules"): (False, False, False, False, False, False, False),
        ("user", "orders"): (True, False, True, True, False, True, False),
        ("user", "access_rules"): (False, False, False, False, False, False, False),
    }
    for (role_name, element_name), permissions in values.items():
        role = find_role(db, role_name)
        element = find_element(db, element_name)
        if db.get(AccessRoleRule, (role.id, element.id)):
            continue
        db.add(
            AccessRoleRule(
                role_id=role.id,
                element_id=element.id,
                **dict(zip(PERMISSIONS, permissions)),
            )
        )


def init_db() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        for role_name in RoleName:
            if not find_role(db, role_name.value):
                db.add(Role(name=role_name.value))
        elements = {
            ElementName.orders.value: "Mock customer orders",
            ElementName.access_rules.value: "Role access rules",
        }
        for name, description in elements.items():
            if not find_element(db, name):
                db.add(BusinessElement(name=name, description=description))
        db.flush()
        seed_rules(db)
        if settings.seed_data:
            seed_user(db, "Administrator", str(settings.admin_email).lower(), settings.admin_password, "admin")
            seed_user(db, "Manager Demo", str(settings.manager_email).lower(), settings.manager_password, "manager")
            seed_user(db, "User Demo", str(settings.user_email).lower(), settings.user_password, "user")
        db.commit()


def user_roles(db: Session, user_id: int) -> list[str]:
    return list(
        db.scalars(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .order_by(Role.name)
        ).all()
    )


def serialize_user(db: Session, user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        is_active=user.is_active,
        roles=user_roles(db, user.id),
    )


def has_permission(db: Session, user_id: int, element_name: str, permission: str) -> bool:
    if permission not in PERMISSIONS:
        return False
    column = getattr(AccessRoleRule, permission)
    result = db.scalar(
        select(func.count())
        .select_from(AccessRoleRule)
        .join(UserRole, UserRole.role_id == AccessRoleRule.role_id)
        .join(BusinessElement, BusinessElement.id == AccessRoleRule.element_id)
        .where(UserRole.user_id == user_id, BusinessElement.name == element_name, column.is_(True))
    )
    return bool(result)


def require_permission(db: Session, user_id: int, element_name: str, permission: str) -> None:
    if not has_permission(db, user_id, element_name, permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
