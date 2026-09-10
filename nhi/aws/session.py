# session.py is responsible for creating and managing an authenticated AWS boto3 Session.
# It supports both ambient credentials (e.g. GitHub Actions OIDC) and STS AssumeRole (e.g. local dev).
import boto3
import boto3.session
from nhi.config import ROLE_ARN

_cached_session = None


def get_session():
    global _cached_session
    if _cached_session is not None:
        return _cached_session

    # In CI/CD with OIDC (or environments without an explicit ROLE_ARN),
    # platform should use the active ambient AWS credentials directly if its going via OIDC route:
    if not ROLE_ARN:
        _cached_session = boto3.session.Session()
        return _cached_session

    # In local development (via runner.sh), this platform assumes the target execution role:
    session_client = boto3.client("sts")
    response = session_client.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="sessionForNHI"
    )
    credentials = response["Credentials"]
    _cached_session = boto3.session.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )
    return _cached_session
