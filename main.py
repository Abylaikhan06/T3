import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.responses import FileResponse


load_dotenv()
BASE_DIR = Path(__file__).resolve().parent


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


def validate_password(value: str) -> str:
    if len(value) < 8 or len(value.encode("utf-8")) > 72:
        raise ValueError("Password must be 8 to 72 bytes long")
    if not any(character.islower() for character in value):
        raise ValueError("Password must contain a lowercase letter")
    if not any(character.isupper() for character in value):
        raise ValueError("Password must contain an uppercase letter")
    if not any(character.isdigit() for character in value):
        raise ValueError("Password must contain a digit")
    if not any(not character.isalnum() for character in value):
        raise ValueError("Password must contain a special character")
    return value


def normalize_name(value: str) -> str:
    value = " ".join(value.split())
    if len(value) < 2 or len(value) > 120:
        raise ValueError("Full name must contain from 2 to 120 characters")
    if not all(character.isalpha() or character in " -'" for character in value):
        raise ValueError("Full name may contain only letters, spaces, apostrophes and hyphens")
    return value


settings = read_settings()
engine_options = {}
if settings.database_url.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(settings.database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)


class BusinessElement(Base):
    __tablename__ = "business_elements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)


class AccessRoleRule(Base):
    __tablename__ = "access_role_rules"

    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    element_id: Mapped[int] = mapped_column(ForeignKey("business_elements.id"), primary_key=True)
    read_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    read_all_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    create_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    update_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    update_all_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delete_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delete_all_permission: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SessionToken(Base):
    __tablename__ = "sessions"

    token_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class RoleName(str, Enum):
    admin = "admin"
    manager = "manager"
    user = "user"


class ElementName(str, Enum):
    orders = "orders"
    access_rules = "access_rules"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str
    email: EmailStr
    password: str
    password_repeat: str

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        return normalize_name(value)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: EmailStr) -> str:
        return str(value).lower()

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        return validate_password(value)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.password_repeat:
            raise ValueError("Passwords do not match")
        return self


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: EmailStr) -> str:
        return str(value).lower()


class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str | None = None
    email: EmailStr | None = None

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str | None) -> str | None:
        return normalize_name(value) if value is not None else value

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: EmailStr | None) -> str | None:
        return str(value).lower() if value is not None else value

    @model_validator(mode="after")
    def require_update(self):
        if self.full_name is None and self.email is None:
            raise ValueError("At least one profile field is required")
        return self


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    is_active: bool
    roles: list[str]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class RuleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    read_permission: bool = False
    read_all_permission: bool = False
    create_permission: bool = False
    update_permission: bool = False
    update_all_permission: bool = False
    delete_permission: bool = False
    delete_all_permission: bool = False


class OrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        value = " ".join(value.split())
        if not any(character.isalnum() for character in value):
            raise ValueError("Title must contain letters or digits")
        return value


def get_db():
    with SessionLocal() as db:
        yield db


DbSession = Annotated[Session, Depends(get_db)]
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
    rule_values = {
        ("admin", "orders"): (True, True, True, True, True, True, True),
        ("admin", "access_rules"): (True, True, True, True, True, True, True),
        ("manager", "orders"): (True, True, True, True, True, False, False),
        ("manager", "access_rules"): (False, False, False, False, False, False, False),
        ("user", "orders"): (True, False, True, True, False, True, False),
        ("user", "access_rules"): (False, False, False, False, False, False, False),
    }
    for (role_name, element_name), permissions in rule_values.items():
        role = find_role(db, role_name)
        element = find_element(db, element_name)
        if db.get(AccessRoleRule, (role.id, element.id)):
            continue
        db.add(
            AccessRoleRule(
                role_id=role.id,
                element_id=element.id,
                read_permission=permissions[0],
                read_all_permission=permissions[1],
                create_permission=permissions[2],
                update_permission=permissions[3],
                update_all_permission=permissions[4],
                delete_permission=permissions[5],
                delete_all_permission=permissions[6],
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


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbSession,
) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = int(payload["sub"])
        token_id = str(payload["jti"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    token = db.get(SessionToken, token_id)
    user = db.get(User, user_id)
    if not token or token.user_id != user_id or token.revoked or not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is inactive")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
PERMISSIONS = {
    "read_permission",
    "read_all_permission",
    "create_permission",
    "update_permission",
    "update_all_permission",
    "delete_permission",
    "delete_all_permission",
}


def has_permission(db: Session, user_id: int, element_name: str, permission: str) -> bool:
    if permission not in PERMISSIONS:
        return False
    permission_column = getattr(AccessRoleRule, permission)
    result = db.scalar(
        select(func.count())
        .select_from(AccessRoleRule)
        .join(UserRole, UserRole.role_id == AccessRoleRule.role_id)
        .join(BusinessElement, BusinessElement.id == AccessRoleRule.element_id)
        .where(
            UserRole.user_id == user_id,
            BusinessElement.name == element_name,
            permission_column.is_(True),
        )
    )
    return bool(result)


def require_permission(db: Session, user_id: int, element_name: str, permission: str) -> None:
    if not has_permission(db, user_id, element_name, permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


MOCK_ORDERS = [
    {"id": 1, "title": "Laptop order", "amount": Decimal("1500.00"), "owner_email": str(settings.user_email).lower()},
    {"id": 2, "title": "Office supplies", "amount": Decimal("250.00"), "owner_email": str(settings.manager_email).lower()},
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="T3 Authentication and Authorization API",
    description="Custom JWT authentication and role-based access control demo.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
def root() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
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


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest, db: DbSession) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == data.email))
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(access_token=create_token(db, user.id), user=serialize_user(db, user))


@app.post("/auth/logout")
def logout(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    current_user: CurrentUser,
    db: DbSession,
) -> dict[str, str]:
    payload = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    token = db.get(SessionToken, payload["jti"])
    token.revoked = True
    db.commit()
    return {"message": "Logged out"}


@app.get("/users/me", response_model=UserResponse)
def get_profile(current_user: CurrentUser, db: DbSession) -> UserResponse:
    return serialize_user(db, current_user)


@app.put("/users/me", response_model=UserResponse)
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


@app.delete("/users/me")
def delete_profile(current_user: CurrentUser, db: DbSession) -> dict[str, str]:
    current_user.is_active = False
    tokens = db.scalars(select(SessionToken).where(SessionToken.user_id == current_user.id)).all()
    for token in tokens:
        token.revoked = True
    db.commit()
    return {"message": "Account deactivated and sessions closed"}


@app.get("/resources/orders")
def list_orders(current_user: CurrentUser, db: DbSession) -> list[dict]:
    require_permission(db, current_user.id, ElementName.orders.value, "read_permission")
    if has_permission(db, current_user.id, ElementName.orders.value, "read_all_permission"):
        return MOCK_ORDERS
    return [order for order in MOCK_ORDERS if order["owner_email"] == current_user.email]


@app.post("/resources/orders", status_code=status.HTTP_201_CREATED)
def create_order(data: OrderRequest, current_user: CurrentUser, db: DbSession) -> dict:
    require_permission(db, current_user.id, ElementName.orders.value, "create_permission")
    order = {
        "id": max((order["id"] for order in MOCK_ORDERS), default=0) + 1,
        "title": data.title,
        "amount": data.amount,
        "owner_email": current_user.email,
    }
    MOCK_ORDERS.append(order)
    return order


@app.patch("/resources/orders/{order_id}")
def update_order(order_id: int, data: OrderRequest, current_user: CurrentUser, db: DbSession) -> dict:
    order = next((item for item in MOCK_ORDERS if item["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    allowed = has_permission(db, current_user.id, ElementName.orders.value, "update_all_permission") or (
        order["owner_email"] == current_user.email
        and has_permission(db, current_user.id, ElementName.orders.value, "update_permission")
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    order.update(title=data.title, amount=data.amount)
    return order


@app.delete("/resources/orders/{order_id}")
def delete_order(order_id: int, current_user: CurrentUser, db: DbSession) -> dict[str, str]:
    order = next((item for item in MOCK_ORDERS if item["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    allowed = has_permission(db, current_user.id, ElementName.orders.value, "delete_all_permission") or (
        order["owner_email"] == current_user.email
        and has_permission(db, current_user.id, ElementName.orders.value, "delete_permission")
    )
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    MOCK_ORDERS.remove(order)
    return {"message": "Order deleted"}


@app.get("/admin/rules")
def list_rules(current_user: CurrentUser, db: DbSession) -> list[dict]:
    require_permission(db, current_user.id, ElementName.access_rules.value, "read_all_permission")
    rows = db.execute(
        select(AccessRoleRule, Role.name, BusinessElement.name)
        .join(Role, Role.id == AccessRoleRule.role_id)
        .join(BusinessElement, BusinessElement.id == AccessRoleRule.element_id)
        .order_by(Role.name, BusinessElement.name)
    ).all()
    return [
        {
            "role": role_name,
            "element": element_name,
            **{permission: getattr(rule, permission) for permission in PERMISSIONS},
        }
        for rule, role_name, element_name in rows
    ]


@app.put("/admin/rules/{role_name}/{element_name}")
def update_rule(
    role_name: RoleName,
    element_name: ElementName,
    data: RuleUpdateRequest,
    current_user: CurrentUser,
    db: DbSession,
) -> dict:
    require_permission(db, current_user.id, ElementName.access_rules.value, "update_all_permission")
    role = find_role(db, role_name.value)
    element = find_element(db, element_name.value)
    rule = db.get(AccessRoleRule, (role.id, element.id))
    values = data.model_dump()
    for name, value in values.items():
        setattr(rule, name, value)
    db.commit()
    return {"role": role_name.value, "element": element_name.value, **values}
