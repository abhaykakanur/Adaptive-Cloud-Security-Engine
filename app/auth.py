from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
import os

from dotenv import load_dotenv
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------- PASSWORD ----------------

def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)


# ---------------- TOKEN ----------------

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    token = jwt.encode(
        to_encode,
        JWT_SECRET,
        algorithm=ALGORITHM
    )

    return token