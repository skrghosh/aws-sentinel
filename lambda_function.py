import boto3
import botocore
import json
from datetime import datetime

def get_wildcard_policies():
    findings = []
    iam = boto3.client("iam")
    users = iam.list_users()["Users"]
    for user in users:
        uname = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=uname)
        for pol in attached["AttachedPolicies"]:
            pol_ver = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=pol["PolicyArn"],
                VersionId=pol_ver
            )["PolicyVersion"]["Document"]
            statements = doc["Statement"]
            if not isinstance(statements, list):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") == "Allow" and (
                    stmt.get("Action") == "*" or stmt.get("Action") == ["*"]
                ):
                    findings.append({
                        "user": uname,
                        "policy": pol["PolicyName"],
                        "issue": "Wildcard action",
                    })
                if "AdministratorAccess" in pol["PolicyName"]:
                    findings.append({
                        "user": uname,
                        "policy": pol["PolicyName"],
                        "issue": "AdministratorAccess attached",
                    })
    return findings

def find_public_buckets():
    findings = []
    s3 = boto3.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        bucket_name = bucket["Name"]
        # Check bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
            if '"Principal":"*"' in policy or '"Effect":"Allow"' in policy and '"Principal":"*"' in policy:
                findings.append({
                    "bucket": bucket_name,
                    "issue": "Bucket policy allows public access"
                })
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code != "NoSuchBucketPolicy":
                raise

        # Check bucket ACL
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            grantee = grant["Grantee"]
            if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                findings.append({
                    "bucket": bucket_name,
                    "issue": "Bucket ACL allows public access"
                })
    return findings

def lambda_handler(event, context):
    iam_results = get_wildcard_policies()
    s3_results = find_public_buckets()
    report = {
        "IAM": iam_results,
        "S3": s3_results
    }
    s3 = boto3.client("s3")
    report_key = f"scan-results/report_{datetime.utcnow().isoformat()}.json"
    s3.put_object(
        Bucket="open-aws-sentinel-reports",   # <---- PUT YOUR BUCKET NAME HERE
        Key=report_key,
        Body=json.dumps(report, indent=2).encode("utf-8"),
        ContentType="application/json"
    )
    return {"status": "done", "report_s3_key": report_key}
