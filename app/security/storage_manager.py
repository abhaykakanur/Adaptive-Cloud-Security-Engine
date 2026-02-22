import boto3
import os
from datetime import datetime
from botocore.exceptions import ClientError


AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
AWS_BUCKET = os.getenv("AWS_BUCKET_NAME")


s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name=AWS_REGION,
)


# ---------------- STORAGE CLASS DECISION ----------------

def get_storage_class(risk: str):

    # Upload stage
    if risk == "LOW":
        return "STANDARD"

    elif risk == "MEDIUM":
        return "STANDARD"

    else:   # HIGH
        return "STANDARD_IA"


# ---------------- ROTATE STORAGE ----------------

def rotate_file_storage(key, new_class):

    try:

        s3.copy_object(
            Bucket=AWS_BUCKET,
            CopySource={
                "Bucket": AWS_BUCKET,
                "Key": key
            },
            Key=key,
            StorageClass=new_class,
            MetadataDirective="COPY"
        )

        print(f"Rotated {key} → {new_class}")
        return "ROTATED"

    except ClientError as e:

        print("Rotation error:", e)
        return "FAILED"


# ---------------- GET CURRENT CLASS ----------------

def get_current_storage_class(key):

    meta = s3.head_object(
        Bucket=AWS_BUCKET,
        Key=key
    )

    return meta.get("StorageClass", "STANDARD")


# ---------------- LOG ROTATION ----------------

def log_rotation(user, filename, new_class):

    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.utcnow()} | ROTATE | {user} | {filename} | {new_class}\n"
        )