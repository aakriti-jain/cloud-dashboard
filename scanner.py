import boto3
import json
import os
from datetime import datetime, timezone


def run_scan():
    print("🚀 Running AWS Scan...")

    findings = []

    # -------------------------
    # S3 CHECK
    # -------------------------
    try:
        s3 = boto3.client('s3')
        buckets = s3.list_buckets()['Buckets']

        print(f"Found {len(buckets)} buckets")

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

            except Exception as e:
                print(f"S3 error for {name}: {e}")

    except Exception as e:
        print("S3 scan failed:", e)


    # -------------------------
    # IAM CHECK
    # -------------------------
    try:
        iam = boto3.client('iam')
        policies = iam.list_policies(Scope='Local')['Policies']

        print(f"Found {len(policies)} IAM policies")

        for policy in policies:
            if "FullAccess" in policy['PolicyName']:
                findings.append({
                    "resource": policy['PolicyName'],
                    "type": "IAM",
                    "issue": "Overly permissive policy",
                    "severity": "HIGH"
                })

    except Exception as e:
        print("IAM scan failed:", e)


    # -------------------------
    # ENSURE REPORTS FOLDER
    # -------------------------
    if not os.path.exists("reports"):
        os.makedirs("reports")


    # -------------------------
    # UNIQUE TIMESTAMP (FIXED)
    # -------------------------
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')

    filename = f"reports/report_{timestamp}.json"


    # -------------------------
    # SAVE REPORT
    # -------------------------
    with open(filename, "w") as f:
        json.dump(findings, f, indent=4)

    print(f"✅ Report saved: {filename}")
    print(f"🔍 Findings count: {len(findings)}")

    return findings