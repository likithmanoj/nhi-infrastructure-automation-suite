import json
from datetime import datetime, timezone
import botocore.exceptions
from nhi.aws.session import get_session
from nhi.config import BUCKET_NAME


def upload_file(file_name: str) -> None:
    session = get_session()
    s3_client = session.client("s3")
    try:
        s3_client.upload_file(file_name, BUCKET_NAME, file_name)
        print(f"File '{file_name}' uploaded to bucket '{BUCKET_NAME}' successfully.")
    except botocore.exceptions.ClientError as e:
        print(f"Error uploading file: {e}")


def persist_scan_artifact(scan_data: dict, prefix: str = "scans/") -> str | None:
    """Persists a complete scan artifact dictionary directly to S3 as JSON."""
    session = get_session()
    s3_client = session.client("s3")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{prefix.rstrip('/')}/scan_{timestamp}.json"

    try:
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=json.dumps(scan_data, indent=2, default=str),
            ContentType="application/json",
        )
        print(f"Scan artifact saved to s3://{BUCKET_NAME}/{key}")
        return key
    except botocore.exceptions.ClientError as e:
        print(f"Error persisting scan artifact: {e}")
        return None


def fetch_latest_scan(prefix: str = "scans/") -> dict | None:
    """Finds and downloads the most recently modified scan artifact from S3."""
    session = get_session()
    s3_client = session.client("s3")
    clean_prefix = prefix.rstrip("/") + "/"

    try:
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix=clean_prefix,
        )

        contents = response.get("Contents", [])
        json_objects = [obj for obj in contents if obj["Key"].endswith(".json")]

        if not json_objects:
            return None

        latest_obj = max(json_objects, key=lambda x: x["LastModified"])
        latest_key = latest_obj["Key"]

        get_resp = s3_client.get_object(Bucket=BUCKET_NAME, Key=latest_key)
        content_body = get_resp["Body"].read().decode("utf-8")
        return json.loads(content_body)

    except botocore.exceptions.ClientError as e:
        print(f"Error fetching latest scan artifact: {e}")
        return None