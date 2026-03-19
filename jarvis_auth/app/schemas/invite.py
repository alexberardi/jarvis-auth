from datetime import datetime

from pydantic import BaseModel, Field

from jarvis_auth.app.db.models import HouseholdRole


class InviteCreateRequest(BaseModel):
    default_role: HouseholdRole = HouseholdRole.MEMBER
    max_uses: int | None = None
    expires_in_days: int = Field(default=7, ge=1, le=90)


class InviteResponse(BaseModel):
    id: int
    household_id: str
    code: str
    default_role: HouseholdRole
    max_uses: int | None
    use_count: int
    expires_at: datetime
    revoked: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class InviteValidateResponse(BaseModel):
    valid: bool
    household_name: str | None = None


class JoinHouseholdRequest(BaseModel):
    invite_code: str


class JoinHouseholdResponse(BaseModel):
    household_id: str
    household_name: str
    role: HouseholdRole
