import boto3
import json
import os
from datetime import datetime, timezone

def run_scan():
    findings = []

    # --- S3 CHECK ---
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant):
                    findings.append({
                        "resource": name,
                        "type": "S3",
                        "issue": "Public bucket",
                        "severity": "CRITICAL"
                    })
        except:
            pass

    # --- IAM CHECK ---
    iam = boto3.client('iam')
    policies = iam.list_policies(Scope='Local')['Policies']

    for policy in policies:
        if "FullAccess" in policy['PolicyName']:
            findings.append({
                "resource": policy['PolicyName'],
                "type": "IAM",
                "issue": "Overly permissive policy",
                "severity": "HIGH"
            })

    # --- SAVE REPORT ---
    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/report_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M')}.json"

    with open(filename, "w") as f:
        json.dump(findings, f, indent=4)

    return filename