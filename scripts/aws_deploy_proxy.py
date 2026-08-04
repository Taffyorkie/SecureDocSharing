from __future__ import annotations

import argparse
from io import BytesIO
import json
import time
import zipfile

import boto3
from botocore.exceptions import ClientError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy or update AWS file share proxy infrastructure")
    parser.add_argument("--region", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--result-json", required=True)
    return parser.parse_args()


def ensure_bucket(s3_client, bucket_name: str, region: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError:
        kwargs = {"Bucket": bucket_name}
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3_client.create_bucket(**kwargs)
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3_client.put_bucket_cors(
        Bucket=bucket_name,
        CORSConfiguration={
            "CORSRules": [
                {
                    "AllowedHeaders": ["*"],
                    "AllowedMethods": ["GET"],
                    "AllowedOrigins": ["*"],
                    "ExposeHeaders": ["ETag"],
                    "MaxAgeSeconds": 3600,
                }
            ]
        },
    )


def ensure_table(dynamodb_client, table_name: str) -> None:
    try:
        dynamodb_client.describe_table(TableName=table_name)
    except ClientError:
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "shareId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "shareId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        waiter = dynamodb_client.get_waiter("table_exists")
        waiter.wait(TableName=table_name)
    dynamodb_client.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={"AttributeName": "expiresAtEpoch", "Enabled": True},
    )


def ensure_role(iam_client, role_name: str, bucket_name: str, table_name: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        role = iam_client.get_role(RoleName=role_name)["Role"]
        role_arn = role["Arn"]
    except ClientError:
        role = iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
        role_arn = role["Arn"]

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:DeleteObject"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
                "Resource": f"arn:aws:dynamodb:*:*:table/{table_name}",
            },
        ],
    }
    iam_client.put_role_policy(RoleName=role_name, PolicyName="SecureShareProxyPolicy", PolicyDocument=json.dumps(inline_policy))
    return role_arn


def package_lambda_code() -> bytes:
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write("app/aws_proxy_lambda.py", arcname="aws_proxy_lambda.py")
    return zip_buffer.getvalue()


def ensure_lambda(lambda_client, function_name: str, role_arn: str, bucket_name: str, table_name: str) -> None:
    code_zip = package_lambda_code()
    try:
        lambda_client.get_function(FunctionName=function_name)
        lambda_client.update_function_code(FunctionName=function_name, ZipFile=code_zip)
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Role=role_arn,
            Runtime="python3.12",
            Handler="aws_proxy_lambda.handler",
            Timeout=30,
            MemorySize=512,
            Environment={"Variables": {"SHARE_BUCKET_NAME": bucket_name, "SHARE_TABLE_NAME": table_name}},
        )
    except ClientError:
        lambda_client.create_function(
            FunctionName=function_name,
            Role=role_arn,
            Runtime="python3.12",
            Handler="aws_proxy_lambda.handler",
            Timeout=30,
            MemorySize=512,
            Environment={"Variables": {"SHARE_BUCKET_NAME": bucket_name, "SHARE_TABLE_NAME": table_name}},
            Code={"ZipFile": code_zip},
        )

    # Give IAM and Lambda time to settle before URL operations.
    time.sleep(8)


def ensure_function_url(lambda_client, function_name: str) -> str:
    try:
        current = lambda_client.get_function_url_config(FunctionName=function_name)
        function_url = current["FunctionUrl"]
    except ClientError:
        created = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
            Cors={
                "AllowOrigins": ["*"],
                "AllowMethods": ["GET", "POST", "OPTIONS"],
                "AllowHeaders": ["content-type"],
                "MaxAge": 86400,
            },
        )
        function_url = created["FunctionUrl"]

    statement_id = "SecureShareProxyFunctionUrlPublicInvoke"
    try:
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise
    return function_url


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

    s3_client = session.client("s3")
    dynamodb_client = session.client("dynamodb")
    iam_client = session.client("iam")
    lambda_client = session.client("lambda")

    ensure_bucket(s3_client, bucket_name, args.region)
    ensure_table(dynamodb_client, table_name)
    role_arn = ensure_role(iam_client, role_name, bucket_name, table_name)
    ensure_lambda(lambda_client, function_name, role_arn, bucket_name, table_name)
    function_url = ensure_function_url(lambda_client, function_name)

    output = {
        "region": args.region,
        "accountId": account_id,
        "bucketName": bucket_name,
        "tableName": table_name,
        "roleName": role_name,
        "functionName": function_name,
        "functionUrl": function_url,
    }
    with open(args.result_json, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)


if __name__ == "__main__":
    main()