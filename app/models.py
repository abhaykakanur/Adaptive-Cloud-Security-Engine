from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func

from app.database import Base


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)

    is_admin = Column(Boolean, default=False)

    # Security tracking
    failed_attempts = Column(Integer, default=0)
    last_ip = Column(String, nullable=True)
    device_hash = Column(String, nullable=True)
    last_login = Column(DateTime, nullable=True)

    # Trust + Healing
    trust_score = Column(Integer, default=50)
    token_version = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())