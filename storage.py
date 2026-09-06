import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()


B2_ENDPOINT = os.getenv("B2_ENDPOINT")
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APPLICATION_KEY = os.getenv("B2_APPLICATION_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")


if not B2_ENDPOINT:
    raise RuntimeError("B2_ENDPOINT is not configured.")

if not B2_KEY_ID:
    raise RuntimeError("B2_KEY_ID is not configured.")

if not B2_APPLICATION_KEY:
    raise RuntimeError("B2_APPLICATION_KEY is not configured.")

if not B2_BUCKET_NAME:
    raise RuntimeError("B2_BUCKET_NAME is not configured.")


b2_client = boto3.client(
    "s3",
    endpoint_url=B2_ENDPOINT,
    aws_access_key_id=B2_KEY_ID,
    aws_secret_access_key=B2_APPLICATION_KEY,
    region_name="us-east-005"
)


def upload_to_b2(local_file_path, object_name):
    """
    Upload a local file to the private Backblaze B2 bucket.
    """

    b2_client.upload_file(
        local_file_path,
        B2_BUCKET_NAME,
        object_name
    )

    return object_name


def download_from_b2(object_name, local_file_path):
    """
    Download an object from Backblaze B2 to a local temporary path.
    """

    b2_client.download_file(
        B2_BUCKET_NAME,
        object_name,
        local_file_path
    )

    return local_file_path


def delete_from_b2(object_name):
    """
    Permanently delete an object from Backblaze B2.
    """

    b2_client.delete_object(
        Bucket=B2_BUCKET_NAME,
        Key=object_name
    )


def b2_object_exists(object_name):
    """
    Check whether an object exists in the private B2 bucket.
    """

    try:
        b2_client.head_object(
            Bucket=B2_BUCKET_NAME,
            Key=object_name
        )
        return True

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code in ("404", "NoSuchKey", "NotFound"):
            return False

        raise