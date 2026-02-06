from datetime import datetime, timezone
from enum import Enum as PyEnum
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from jarvis_auth.app.db.base import Base


class HouseholdRole(str, PyEnum):
    """Role within a household."""
    MEMBER = "member"
    POWER_USER = "power_user"
    ADMIN = "admin"

    @classmethod
    def has_permission(cls, user_role: "HouseholdRole", required_role: "HouseholdRole") -> bool:
        """Check if user_role meets or exceeds required_role in the hierarchy."""
        hierarchy = {cls.MEMBER: 0, cls.POWER_USER: 1, cls.ADMIN: 2}
        return hierarchy[user_role] >= hierarchy[required_role]


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_refresh_token_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped[User] = relationship("User", back_populates="refresh_tokens")

    @property
    def is_expired(self) -> bool:
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires_at


class AppClient(Base):
    __tablename__ = "app_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    app_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Household(Base):
    """A household that groups users and nodes together."""
    __tablename__ = "households"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid4()),
        index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    memberships: Mapped[list["HouseholdMembership"]] = relationship(
        "HouseholdMembership", back_populates="household", cascade="all, delete-orphan"
    )
    nodes: Mapped[list["NodeRegistration"]] = relationship(
        "NodeRegistration", back_populates="household", cascade="all, delete-orphan"
    )


class HouseholdMembership(Base):
    """Links a user to a household with a specific role."""
    __tablename__ = "household_memberships"
    __table_args__ = (
        UniqueConstraint("household_id", "user_id", name="uq_household_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    household_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("households.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role: Mapped[HouseholdRole] = mapped_column(
        Enum(HouseholdRole, native_enum=False, length=20),
        nullable=False,
        default=HouseholdRole.MEMBER
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    household: Mapped[Household] = relationship("Household", back_populates="memberships")
    user: Mapped[User] = relationship("User")


class NodeRegistration(Base):
    """A node registered to a household."""
    __tablename__ = "node_registrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    household_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("households.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    registered_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    node_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    household: Mapped[Household] = relationship("Household", back_populates="nodes")
    registered_by: Mapped[User | None] = relationship("User")
    service_access: Mapped[list["NodeServiceAccess"]] = relationship(
        "NodeServiceAccess", back_populates="node", cascade="all, delete-orphan"
    )


class NodeServiceAccess(Base):
    """Grants a node access to a specific service."""
    __tablename__ = "node_service_access"
    __table_args__ = (
        UniqueConstraint("node_id", "service_id", name="uq_node_service_access"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    node_id: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("node_registrations.node_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    service_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    granted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    node: Mapped[NodeRegistration] = relationship("NodeRegistration", back_populates="service_access")


class Setting(Base):
    """Runtime settings that can be modified without restarting the service.

    Settings are organized by category and support type coercion.
    If a setting is not in the database, it falls back to the original
    environment variable (env_fallback).

    Multi-tenant scoping:
    - household_id: NULL = system default, set = household-wide
    - node_id: NULL = household-wide, set = node-specific
    - user_id: NULL = node-wide, set = user-specific

    Cascade lookup order: user > node > household > system
    """
    __tablename__ = "settings"
    __table_args__ = (
        UniqueConstraint("key", "household_id", "node_id", "user_id", name="uq_setting_scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    value: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON-encoded for complex types
    value_type: Mapped[str] = mapped_column(String(50), nullable=False)  # string, int, float, bool, json
    category: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    requires_reload: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    env_fallback: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Multi-tenant scoping (all nullable = system default)
    household_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    node_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now())

