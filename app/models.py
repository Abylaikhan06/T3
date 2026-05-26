from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


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
