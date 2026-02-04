from datetime import datetime

from pydantic import BaseModel


# Admin endpoint schemas
class NodeCreateRequest(BaseModel):
    node_id: str
    household_id: str
    name: str
    registered_by_user_id: int | None = None
    services: list[str] | None = None


class NodeCreateResponse(BaseModel):
    node_id: str
    name: str
    household_id: str
    registered_by_user_id: int | None = None
    node_key: str
    created_at: datetime
    services: list[str]


class NodeListItem(BaseModel):
    node_id: str
    name: str
    household_id: str
    registered_by_user_id: int | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_rotated_at: datetime | None = None
    services: list[str]

    model_config = {"from_attributes": True}


class NodeDetailResponse(BaseModel):
    node_id: str
    name: str
    household_id: str
    registered_by_user_id: int | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_rotated_at: datetime | None = None
    services: list["ServiceAccessItem"]

    model_config = {"from_attributes": True}


class ServiceAccessItem(BaseModel):
    service_id: str
    granted_at: datetime
    granted_by: int | None = None

    model_config = {"from_attributes": True}


class NodeRotateKeyResponse(BaseModel):
    node_id: str
    node_key: str
    last_rotated_at: datetime


class NodeDeactivateResponse(BaseModel):
    node_id: str
    is_active: bool


# Service access schemas
class ServiceAccessRequest(BaseModel):
    service_id: str


class ServiceAccessResponse(BaseModel):
    node_id: str
    service_id: str
    granted_at: datetime


# Internal endpoint schemas (for app-to-app validation)
class NodeRegisterInternalRequest(BaseModel):
    node_id: str
    household_id: str
    name: str
    registered_by_user_id: int | None = None
    services: list[str] | None = None


class NodeRegisterInternalResponse(BaseModel):
    node_id: str
    node_key: str


class NodeValidateRequest(BaseModel):
    node_id: str
    node_key: str
    service_id: str


class NodeValidateResponse(BaseModel):
    valid: bool
    node_id: str | None = None
    household_id: str | None = None
    household_member_ids: list[int] | None = None
    reason: str | None = None
