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

            # ---- ACL CHECK ----
            try:
                acl = s3.get_bucket_acl(Bucket=name)

                for grant in acl['Grants']:
                    if 'AllUsers' in str(grant):
                        findings.append({
                            "resource": name,
                            "type": "S3",
                            "issue": "Public bucket (ACL)",
                            "severity": "CRITICAL"
                        })

            except Exception as e:
                print(f"S3 ACL error for {name}: {e}")

            # ---- POLICY CHECK (IMPORTANT ADDITION) ----
            try:
                policy = s3.get_bucket_policy(Bucket=name)

                if '"Principal": "*"' in policy['Policy']:
                    findings.append({
                        "resource": name,
                        "type": "S3",
                        "issue": "Public bucket (Policy)",
                        "severity": "CRITICAL"
                    })

            except Exception:
                # No policy is normal → ignore
                pass

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
            name = policy['PolicyName']

            # Basic detection
            if "FullAccess" in name or "Admin" in name:
                findings.append({
                    "resource": name,
                    "type": "IAM",
                    "issue": "Overly permissive policy name",
                    "severity": "HIGH"
                })

            # Optional deeper check (policy document)
            try:
                version = iam.get_policy(PolicyArn=policy['Arn'])['Policy']['DefaultVersionId']
                doc = iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=version
                )['PolicyVersion']['Document']

                if '"Action": "*"' in json.dumps(doc) and '"Effect": "Allow"' in json.dumps(doc):
                    findings.append({
                        "resource": name,
                        "type": "IAM",
                        "issue": "Wildcard permissions (*)",
                        "severity": "CRITICAL"
                    })

            except Exception:
                pass

    except Exception as e:
        print("IAM scan failed:", e)


    # -------------------------
    # ENSURE REPORTS FOLDER
    # -------------------------
    if not os.path.exists("reports"):
        os.makedirs("reports")


    # -------------------------
    # UNIQUE TIMESTAMP
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