import os
from dotenv import load_dotenv

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Load .env
load_dotenv()

# Get DB URL
DATABASE_URL = os.getenv("DATABASE_URL")

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Needed for SQLite
)

# Session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base for models
Base = declarative_base()