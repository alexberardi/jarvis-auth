from pydantic import BaseModel, EmailStr, Field
from jarvis_auth.app.schemas.user import UserOut


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str | None = None
    password: str = Field(min_length=8, max_length=255)
    invite_code: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut | None = None
    # True when the user logged in with an admin-issued temporary password and
    # clients must force a change via /auth/change-password before normal use.
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class AccountDeleteRequest(BaseModel):
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=255)


class LogoutRequest(BaseModel):
    refresh_token: str
    all_devices: bool = False


class RegisterResponse(BaseModel):
    """Response for user registration, includes tokens and household ID."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut
    household_id: str

