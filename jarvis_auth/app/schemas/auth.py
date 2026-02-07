from pydantic import BaseModel, EmailStr, Field
from jarvis_auth.app.schemas.user import UserOut


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str | None = None
    password: str = Field(min_length=8, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class RegisterResponse(BaseModel):
    """Response for user registration, includes tokens and household ID."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut
    household_id: str

