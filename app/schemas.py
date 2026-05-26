from decimal import Decimal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.validators import normalize_name, validate_password


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
