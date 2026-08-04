from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path

import boto3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cleanup expired AWS secure shares")
    parser.add_argument("--region", required=True)
    parser.add_argument("--proxy-config-json", required=True)
    parser.add_argument("--result-json", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    proxy_config = json.loads(Path(args.proxy_config_json).read_text(encoding="utf-8"))

    session = boto3.Session(region_name=args.region)
    table = session.resource("dynamodb").Table(proxy_config["tableName"])
    s3_client = session.client("s3")

    now_epoch = int(datetime.now(UTC).timestamp())
    removed_count = 0

    scan_kwargs = {
        "ProjectionExpression": "shareId, expiresAtEpoch, #status, s3Key",
        "ExpressionAttributeNames": {"#status": "status"},
    }

    while True:
        response = table.scan(**scan_kwargs)
        for item in response.get("Items", []):
            expired = int(item.get("expiresAtEpoch", 0)) <= now_epoch
            consumed = item.get("status") == "consumed"
            if not expired and not consumed:
                continue
            s3_key = item.get("s3Key")
            if s3_key:
                s3_client.delete_object(Bucket=proxy_config["bucketName"], Key=s3_key)
            table.delete_item(Key={"shareId": item["shareId"]})
            removed_count += 1

        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

    result = {"removedShares": removed_count, "checkedAtEpoch": now_epoch}
    Path(args.result_json).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()