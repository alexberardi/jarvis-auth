from datetime import datetime

from pydantic import BaseModel

from jarvis_auth.app.db.models import HouseholdRole


# Household schemas
class HouseholdCreateRequest(BaseModel):
    name: str


class HouseholdCreateResponse(BaseModel):
    id: str
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class HouseholdUpdateRequest(BaseModel):
    name: str


class HouseholdResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class HouseholdListItem(BaseModel):
    id: str
    name: str
    role: HouseholdRole
    created_at: datetime

    model_config = {"from_attributes": True}


# Member schemas
class MemberAddRequest(BaseModel):
    user_id: int
    role: HouseholdRole = HouseholdRole.MEMBER


class MemberUpdateRequest(BaseModel):
    role: HouseholdRole


class MemberResponse(BaseModel):
    user_id: int
    username: str
    email: str
    role: HouseholdRole
    created_at: datetime

    model_config = {"from_attributes": True}


class MemberListItem(BaseModel):
    user_id: int
    username: str
    email: str
    role: HouseholdRole
    created_at: datetime

    model_config = {"from_attributes": True}


# Internal validation schemas
class HouseholdAccessValidateRequest(BaseModel):
    user_id: int
    household_id: str
    required_role: HouseholdRole


class HouseholdAccessValidateResponse(BaseModel):
    valid: bool
    user_id: int | None = None
    household_id: str | None = None
    role: HouseholdRole | None = None
    reason: str | None = None


class NodeHouseholdValidateRequest(BaseModel):
    node_id: str
    household_id: str


class NodeHouseholdValidateResponse(BaseModel):
    valid: bool
    node_id: str | None = None
    household_id: str | None = None
    reason: str | None = None
