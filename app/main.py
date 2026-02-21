from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from app.security.risk_engine import calculate_risk
from app.security.encryption import encrypt_data, decrypt_data
from app.security.key_splitter import split_key, rebuild_key

from app.database import SessionLocal, engine, Base
from app.models import User
from app.auth import hash_password, verify_password, create_access_token

import os
import boto3
import io
import hashlib
from datetime import datetime
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------

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

Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------- AUTH ----------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme)):

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if not email:
            raise HTTPException(401)

        return email

    except JWTError:
        raise HTTPException(401)


def get_current_admin(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    db_user = db.query(User).filter(User.email == user).first()

    if not db_user or not db_user.is_admin:
        raise HTTPException(403, "Admin only")

    return db_user


# ---------------- AUDIT ----------------


def log_event(user, action, filename):

    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.now()} | {user} | {action} | {filename}\n"
        )


# ---------------- HOME ----------------


@app.get("/")
def home():
    return {"message": "Adaptive Cloud Security Running"}


# ---------------- REGISTER ----------------


@app.post("/register")
def register(email: str, password: str, db: Session = Depends(get_db)):

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "User exists")

    hashed = hash_password(password)

    user = User(
        email=email,
        password=hashed,
        is_admin=False,
    )

    db.add(user)
    db.commit()

    return {"message": "Registered"}


# ---------------- LOGIN ----------------


@app.post("/login")
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):

    user = db.query(User).filter(
        User.email == form.username
    ).first()

    if not user:
        raise HTTPException(400, "Invalid login")

    ip = request.client.host

    ua = request.headers.get("user-agent", "unknown")
    device_hash = hashlib.sha256(ua.encode()).hexdigest()

    if not verify_password(form.password, user.password):

        user.failed_attempts += 1
        db.commit()

        raise HTTPException(400, "Invalid login")

    # ---------- RISK ----------

    risk = calculate_risk(
        user=user,
        ip_address=ip,
        device_hash=device_hash,
        action="login",
    )

    user.failed_attempts = 0
    user.last_ip = ip
    user.device_hash = device_hash
    user.last_login = datetime.utcnow()

    db.commit()

    token = create_access_token(
        data={"sub": user.email}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "risk": risk,
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
    db: Session = Depends(get_db),
):

    data = await file.read()

    db_user = db.query(User).filter(User.email == user).first()

    ip = request.client.host

    ua = request.headers.get("user-agent", "unknown")
    device_hash = hashlib.sha256(ua.encode()).hexdigest()

    ext = file.filename.split(".")[-1].lower()

    # ---------- RISK ----------

    risk = calculate_risk(
        user=db_user,
        ip_address=ip,
        device_hash=device_hash,
        action="upload",
        file_size=len(data),
        file_type=ext,
    )

    # ---------- ENCRYPT ----------

    encrypted_data, key = encrypt_data(
        data=data,
        password=user,
        level=risk,
    )

    main_key = key[0] if isinstance(key, tuple) else key

    # ---------- SPLIT RULE ----------

    if risk == "LOW":
        parts = 2
    elif risk == "MEDIUM":
        parts = 3
    else:
        parts = 5

    threshold = (parts // 2) + 1

    # ---------- SPLIT ----------

    shares = split_key(
        key=main_key,
        parts=parts,
        threshold=threshold,
    )

    # ---------- STORE PARTS ----------

    for i, share in enumerate(shares):

        s3.put_object(
            Bucket=AWS_BUCKET,
            Key=f"{user}/keys/{file.filename}.part{i}",
            Body=share,
        )

    # ---------- STORE FILE ----------

    enc_key = f"{user}/{file.filename}.enc"

    s3.put_object(
        Bucket=AWS_BUCKET,
        Key=enc_key,
        Body=encrypted_data,
    )

    log_event(user, f"UPLOAD-{risk}", file.filename)

    return {
        "message": "Encrypted + Split + Uploaded",
        "risk": risk,
        "file": file.filename,
        "parts": parts,
        "threshold": threshold,
    }


# ---------------- DOWNLOAD ----------------


@app.get("/download/{filename}")
def download_file(
    filename: str,
    user: str = Depends(get_current_user),
):

    enc_key = f"{user}/{filename}.enc"

    try:

        # ---------- GET FILE ----------

        obj = s3.get_object(
            Bucket=AWS_BUCKET,
            Key=enc_key,
        )

        encrypted_data = obj["Body"].read()

        # ---------- GET PARTS ----------

        shares = []

        i = 0

        while True:

            try:

                part = s3.get_object(
                    Bucket=AWS_BUCKET,
                    Key=f"{user}/keys/{filename}.part{i}",
                )

                shares.append(
                    part["Body"].read().decode()
                )

                i += 1

            except:
                break

        if not shares:
            raise HTTPException(404, "Key parts missing")

        # ---------- REBUILD ----------

        rebuilt_key = rebuild_key(shares)

        # ---------- DECRYPT ----------

        original = decrypt_data(
            encrypted_data,
            password=user,
            level="MEDIUM",  # stable for now
        )

        log_event(user, "DOWNLOAD", filename)

        return StreamingResponse(
            io.BytesIO(original),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition":
                f"attachment; filename={filename}"
            },
        )

    except:

        raise HTTPException(404, "File not found")


# ---------------- LIST FILES ----------------


@app.get("/files")
def list_files(user: str = Depends(get_current_user)):

    prefix = f"{user}/"

    res = s3.list_objects_v2(
        Bucket=AWS_BUCKET,
        Prefix=prefix,
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
    user: str = Depends(get_current_user),
):

    s3.delete_object(
        Bucket=AWS_BUCKET,
        Key=f"{user}/{filename}.enc",
    )

    i = 0

    while True:

        try:

            s3.delete_object(
                Bucket=AWS_BUCKET,
                Key=f"{user}/keys/{filename}.part{i}",
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
    db: Session = Depends(get_db),
):

    users = db.query(User).all()

    return {
        "total": len(users),
        "users": [
            {
                "email": u.email,
                "is_admin": u.is_admin,
            }
            for u in users
        ],
    }


# ---------------- ADMIN LOGS ----------------


@app.get("/admin/logs")
def admin_logs(admin: User = Depends(get_current_admin)):

    try:

        with open("audit.log") as f:
            logs = f.readlines()

        return {
            "total": len(logs),
            "logs": logs[-50:],
        }

    except:

        return {"logs": []}