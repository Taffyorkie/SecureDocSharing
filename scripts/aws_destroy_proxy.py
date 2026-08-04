from __future__ import annotations

import argparse
import json

import boto3
from botocore.exceptions import ClientError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Destroy AWS share proxy infrastructure")
    parser.add_argument("--region", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--result-json", required=True)
    return parser.parse_args()


def delete_function_url(lambda_client, function_name: str, actions: list[str]) -> None:
    try:
        lambda_client.delete_function_url_config(FunctionName=function_name)
        actions.append("Deleted Lambda function URL config")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise

    try:
        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId="SecureShareProxyFunctionUrlPublicInvoke",
        )
        actions.append("Removed Lambda function URL permission")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code not in {"ResourceNotFoundException", "ResourceNotFound"}:
            raise


def delete_lambda(lambda_client, function_name: str, actions: list[str]) -> None:
    delete_function_url(lambda_client, function_name, actions)
    try:
        lambda_client.delete_function(FunctionName=function_name)
        actions.append("Deleted Lambda function")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


def empty_and_delete_bucket(s3_client, bucket_name: str, actions: list[str]) -> None:
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete = []
            for version in page.get("Versions", []):
                to_delete.append({"Key": version["Key"], "VersionId": version["VersionId"]})
            for marker in page.get("DeleteMarkers", []):
                to_delete.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
            if to_delete:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete})
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "NoSuchBucket":
            return
        if code not in {"NoSuchBucket", "NotFound", "NoSuchKey"}:
            # Fallback to non-versioned listing.
            pass

    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete = [{"Key": item["Key"]} for item in page.get("Contents", [])]
            if to_delete:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete})
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "NoSuchBucket":
            return
        raise

    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        actions.append("Deleted S3 bucket")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code not in {"NoSuchBucket", "NotFound"}:
            raise


def delete_table(dynamodb_client, table_name: str, actions: list[str]) -> None:
    try:
        dynamodb_client.delete_table(TableName=table_name)
        actions.append("Deleted DynamoDB table")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


def delete_role(iam_client, role_name: str, actions: list[str]) -> None:
    try:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName="SecureShareProxyPolicy")
        actions.append("Deleted IAM inline role policy")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            raise

    try:
        iam_client.delete_role(RoleName=role_name)
        actions.append("Deleted IAM role")
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            raise


def main() -> None:
    args = parse_args()

    session = boto3.Session(region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    sanitized_prefix = "".join(char if char.isalnum() or char == "-" else "-" for char in args.prefix.lower()).strip("-")
    base_name = f"{sanitized_prefix}-{account_id}-{args.region}"

    bucket_name = f"{base_name}-share-bucket"
    table_name = f"{sanitized_prefix}-share-table"
    role_name = f"{sanitized_prefix}-lambda-role"
    function_name = f"{sanitized_prefix}-proxy"

    lambda_client = session.client("lambda")
    s3_client = session.client("s3")
    dynamodb_client = session.client("dynamodb")
    iam_client = session.client("iam")

    actions: list[str] = []

    delete_lambda(lambda_client, function_name, actions)
    delete_table(dynamodb_client, table_name, actions)
    empty_and_delete_bucket(s3_client, bucket_name, actions)
    delete_role(iam_client, role_name, actions)

    result = {
        "region": args.region,
        "accountId": account_id,
        "functionName": function_name,
        "tableName": table_name,
        "bucketName": bucket_name,
        "roleName": role_name,
        "actions": actions,
    }
    with open(args.result_json, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)


if __name__ == "__main__":
    main()