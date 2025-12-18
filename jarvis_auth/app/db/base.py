from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""

    pass


# Import models to ensure metadata is populated.
from jarvis_auth.app.db import models  # noqa: E402,F401

