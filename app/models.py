from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from datetime import datetime
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

    # Admin
    is_admin = Column(Boolean, default=False)

    # Security Tracking
    trust_score = Column(Float, default=1.0)   # 0 → bad, 1 → trusted
    failed_attempts = Column(Integer, default=0)

    last_login = Column(DateTime, default=None)

    last_ip = Column(String, default=None)
    device_hash = Column(String, default=None)