"""Contain an exposed IAM access key reported by AWS Health, then tell humans.

Order matters: contain first (deactivate + deny), investigate second (CloudTrail),
notify third. Deleting the commit that leaked the key does nothing for exposure.
"""
import json
import os
from datetime import datetime, timedelta, timezone

import boto3

iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")
sns = boto3.client("sns")

DENY_ALL = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
})


def recent_activity(key_id: str) -> list[str]:
    start = datetime.now(timezone.utc) - timedelta(hours=24)
    resp = cloudtrail.lookup_events(
        LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": key_id}],
        StartTime=start, MaxResults=50,
    )
    return [f'{e["EventTime"].isoformat()} {e.get("EventSource", "")} {e["EventName"]}'
            for e in resp.get("Events", [])]


def handler(event, _context):
    detail = event.get("detail", {})
    entities = [e.get("entityValue") for e in detail.get("affectedEntities", []) if e.get("entityValue")]
    remediate = os.environ.get("AUTO_REMEDIATE", "true").lower() == "true"
    report = []

    for key_id in entities:
        user = iam.get_access_key_last_used(AccessKeyId=key_id).get("UserName")
        actions = []
        if remediate and user:
            iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
            iam.put_user_policy(UserName=user, PolicyName="ExposedKeyQuarantineDenyAll",
                                PolicyDocument=DENY_ALL)
            actions = ["key deactivated", "deny-all policy attached"]
        activity = recent_activity(key_id)
        report.append({"access_key_id": key_id[:8] + "********", "user": user,
                       "actions": actions or ["notify only"],
                       "api_calls_last_24h": len(activity), "sample": activity[:10]})

    sns.publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject="Exposed AWS access key contained" if remediate else "Exposed AWS access key detected",
        Message=json.dumps({"event": detail.get("eventTypeCode"), "keys": report}, indent=2, default=str),
    )
    return {"handled": len(report)}
