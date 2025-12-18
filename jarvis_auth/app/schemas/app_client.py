from datetime import datetime

from pydantic import BaseModel


class AppClientCreateRequest(BaseModel):
    app_id: str
    name: str


class AppClientCreateResponse(BaseModel):
    app_id: str
    name: str
    key: str
    created_at: datetime
    last_rotated_at: datetime | None = None


class AppClientRotateResponse(BaseModel):
    app_id: str
    key: str
    last_rotated_at: datetime | None = None


class AppClientRevokeResponse(BaseModel):
    app_id: str
    is_active: bool


class AppClientListItem(BaseModel):
    app_id: str
    name: str
    is_active: bool
    created_at: datetime
    last_rotated_at: datetime | None = None

    model_config = {"from_attributes": True}

