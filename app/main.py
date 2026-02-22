from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse

from sqlalchemy.orm import Session
from jose import JWTError, jwt

import boto3
import os
import io
import hashlib

from datetime import datetime, timedelta
from dotenv import load_dotenv


# ---------------- ENV ----------------

load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
AWS_BUCKET = os.getenv("AWS_BUCKET_NAME")

JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"


# ---------------- AWS ----------------

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name=AWS_REGION,
)


# ---------------- APP ----------------

app = FastAPI()


# ---------------- DB ----------------

from app.database import SessionLocal, engine, Base
from app.models import User

Base.metadata.create_all(bind=engine)


# ---------------- DEP ----------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------- SECURITY ----------------

from app.auth import hash_password, verify_password, create_access_token

from app.security.risk_engine import calculate_risk
from app.security.encryption import encrypt_data, decrypt_data
from app.security.key_splitter import split_key, rebuild_key

from app.security.storage_manager import (
    get_storage_class,
    rotate_file_storage,
    log_rotation
)


# ---------------- AUTH ----------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])

        email = payload.get("sub")
        ver = payload.get("ver")

        if not email:
            raise HTTPException(401)

        user = db.query(User).filter(User.email == email).first()

        if not user:
            raise HTTPException(401)

        # Token invalidation
        if ver != user.token_version:
            raise HTTPException(401, "Token expired")

        return email

    except JWTError:
        raise HTTPException(401)


# ---------------- ADMIN ----------------

def get_current_admin(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(User.email == current_user).first()

    if not user or not user.is_admin:
        raise HTTPException(403, "Admin only")

    return user


# ---------------- AUDIT ----------------

def log_event(user, action, filename):

    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.utcnow()} | {user} | {action} | {filename}\n"
        )


# ---------------- SELF HEAL ----------------

def self_heal(user: User, db: Session):

    # Invalidate tokens
    user.token_version += 1

    # Reset trust
    user.trust_score = 50

    # Lock account
    user.locked_until = datetime.utcnow() + timedelta(minutes=5)

    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.utcnow()} | SELF_HEAL | {user.email}\n"
        )

    db.commit()

    # ---------- ROTATE ALL FILES TO GLACIER ----------

    prefix = f"{user.email}/"

    files = s3.list_objects_v2(
        Bucket=AWS_BUCKET,
        Prefix=prefix
    )

    if "Contents" in files:

        for obj in files["Contents"]:

            key = obj["Key"]

            if key.endswith(".enc"):

                rotate_file_storage(key, "STANDARD_IA")

                log_rotation(
                    user.email,
                    key,
                    "GLACIER"
                )


# ---------------- RECOVER STORAGE ----------------

def recover_storage(user_email: str):

    prefix = f"{user_email}/"

    files = s3.list_objects_v2(
        Bucket=AWS_BUCKET,
        Prefix=prefix
    )

    if "Contents" not in files:
        return

    for obj in files["Contents"]:

        key = obj["Key"]

        if key.endswith(".enc"):

            rotate_file_storage(key, "STANDARD")

            log_rotation(
                user_email,
                key,
                "STANDARD"
            )


# ---------------- HOME ----------------

@app.get("/")
def home():
    return {"message": "Adaptive Cloud Security Engine Running"}


# ---------------- REGISTER ----------------

@app.post("/register")
def register(
    email: str,
    password: str,
    db: Session = Depends(get_db)
):

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "User exists")

    hashed = hash_password(password)

    user = User(
        email=email,
        password=hashed
    )

    db.add(user)
    db.commit()

    return {"message": "Registered"}


# ---------------- LOGIN ----------------

@app.post("/login")
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.email == form.username
    ).first()

    if not user:
        raise HTTPException(400, "Invalid login")

    now = datetime.utcnow()

    # Check lock
    if user.locked_until and user.locked_until > now:

        self_heal(user, db)

        raise HTTPException(
            403,
            f"Account locked until {user.locked_until}"
        )

    ip = request.client.host

    ua = request.headers.get("user-agent", "unknown")
    device_hash = hashlib.sha256(ua.encode()).hexdigest()

    # Wrong password
    if not verify_password(form.password, user.password):

        user.failed_attempts += 1

        # Lock after 5 fails
        if user.failed_attempts >= 5:
            user.locked_until = now + timedelta(minutes=5)
            self_heal(user, db)

        db.commit()

        raise HTTPException(400, "Invalid login")

    # Reset on success
    user.failed_attempts = 0
    user.locked_until = None

    # Recover storage if healed
    recover_storage(user.email)

    # Risk
    risk = calculate_risk(
        user=user,
        ip_address=ip,
        device_hash=device_hash,
        action="login"
    )

    # Self-heal on high risk
    if risk == "HIGH":
        self_heal(user, db)

    user.last_ip = ip
    user.device_hash = device_hash
    user.last_login = now

    db.commit()

    token = create_access_token(
        data={
            "sub": user.email,
            "ver": user.token_version
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "risk": risk
    }


# ---------------- PROFILE ----------------

@app.get("/me")
def me(user: str = Depends(get_current_user)):
    return {"email": user}


# ---------------- UPLOAD ----------------

@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    data = await file.read()

    db_user = db.query(User).filter(User.email == user).first()

    ip = request.client.host

    ua = request.headers.get("user-agent", "unknown")
    device_hash = hashlib.sha256(ua.encode()).hexdigest()

    ext = file.filename.split(".")[-1].lower()

    # Risk
    risk = calculate_risk(
        user=db_user,
        ip_address=ip,
        device_hash=device_hash,
        action="upload",
        file_size=len(data),
        file_type=ext
    )

    # Encrypt
    encrypted_data, key = encrypt_data(
        data=data,
        password=user,
        level=risk
    )

    # Split parts
    if risk == "LOW":
        parts = 2
    elif risk == "MEDIUM":
        parts = 3
    else:
        parts = 5

    main_key = key[0] if isinstance(key, tuple) else key

    shares = split_key(
        key=main_key,
        parts=parts,
        threshold=(parts // 2) + 1
    )

    # Store key parts
    for i, share in enumerate(shares):

        s3.put_object(
            Bucket=AWS_BUCKET,
            Key=f"{user}/keys/{file.filename}.part{i}",
            Body=share
        )

    # Storage tier
    storage_class = get_storage_class(risk)

    # Store file
    enc_key = f"{user}/{file.filename}.enc"

    s3.put_object(
        Bucket=AWS_BUCKET,
        Key=enc_key,
        Body=encrypted_data,
        StorageClass=storage_class
    )

    log_rotation(user, file.filename, storage_class)

    log_event(user, f"UPLOAD-{risk}", enc_key)

    return {
        "message": "Encrypted + Split + Rotated + Uploaded",
        "risk": risk,
        "storage": storage_class,
        "file": enc_key
    }


# ---------------- DOWNLOAD ----------------

@app.get("/download/{filename}")
def download_file(
    filename: str,
    user: str = Depends(get_current_user)
):

    enc_key = f"{user}/{filename}.enc"

    try:

        # Get file
        obj = s3.get_object(
            Bucket=AWS_BUCKET,
            Key=enc_key
        )

        encrypted_data = obj["Body"].read()

        # Get key parts
        shares = []

        i = 0
        while True:

            try:

                part = s3.get_object(
                    Bucket=AWS_BUCKET,
                    Key=f"{user}/keys/{filename}.part{i}"
                )

                shares.append(
                    part["Body"].read().decode()
                )

                i += 1

            except:
                break

        if len(shares) < 2:

            self_heal(
                db.query(User).filter(User.email == user).first(),
                SessionLocal()
            )

            raise HTTPException(403, "Security recovery in progress")

        rebuild_key(shares)

        # Decrypt
        original = decrypt_data(
            encrypted_data,
            password=user,
            level="MEDIUM"
        )

        log_event(user, "DOWNLOAD", filename)

        return StreamingResponse(
            io.BytesIO(original),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition":
                f"attachment; filename={filename}"
            }
        )

    except:
        raise HTTPException(404, "File not found")


# ---------------- LIST FILES ----------------

@app.get("/files")
def list_files(user: str = Depends(get_current_user)):

    prefix = f"{user}/"

    res = s3.list_objects_v2(
        Bucket=AWS_BUCKET,
        Prefix=prefix
    )

    files = []

    if "Contents" in res:

        for obj in res["Contents"]:

            name = obj["Key"].replace(prefix, "")

            if name.endswith(".enc"):
                files.append(name.replace(".enc", ""))

    return {"files": files}


# ---------------- DELETE ----------------

@app.delete("/delete/{filename}")
def delete_file(
    filename: str,
    user: str = Depends(get_current_user)
):

    s3.delete_object(
        Bucket=AWS_BUCKET,
        Key=f"{user}/{filename}.enc"
    )

    i = 0

    while True:

        try:

            s3.delete_object(
                Bucket=AWS_BUCKET,
                Key=f"{user}/keys/{filename}.part{i}"
            )

            i += 1

        except:
            break

    log_event(user, "DELETE", filename)

    return {"message": "Deleted"}


# ---------------- ADMIN USERS ----------------

@app.get("/admin/users")
def admin_users(
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):

    users = db.query(User).all()

    return {
        "total": len(users),
        "users": [
            {
                "email": u.email,
                "is_admin": u.is_admin,
                "trust": u.trust_score
            }
            for u in users
        ]
    }


# ---------------- ADMIN LOGS ----------------

@app.get("/admin/logs")
def admin_logs(admin: User = Depends(get_current_admin)):

    try:

        with open("audit.log") as f:
            logs = f.readlines()

        return {
            "total": len(logs),
            "logs": logs[-50:]
        }

    except:
        return {"logs": []}