# AWS Sentinel – Open Source AWS Security Scanner

This tool is a lightweight Lambda-based tool to audit your AWS account for the most common and dangerous misconfigurations:
- Over-privileged IAM users
- Public S3 buckets

## How it works

- Deploys as an AWS Lambda function (Python)
- On manual or scheduled run, scans IAM and S3 for risky settings
- Saves a JSON report in an S3 bucket

## Setup Instructions

### 1. Deploy Lambda Function

- Copy `lambda_function.py` and zip it:
    ```
    zip lambda_function.zip lambda_function.py
    ```
- In AWS Lambda console:
    - Create a function (Python 3.12+)
    - Upload the zip
    - Set the handler to `lambda_function.lambda_handler`

### 2. Create a Private S3 Bucket

- Example name: `open-aws-sentinel-reports-yourname`
- Block all public access

### 3. Permissions

Attach these AWS policies to the Lambda role:
- `IAMReadOnlyAccess`
- `AmazonS3ReadOnlyAccess`
- Or use an inline policy with:
    - `iam:ListUsers`
    - `iam:ListAttachedUserPolicies`
    - `iam:GetPolicy`
    - `iam:GetPolicyVersion`
    - `s3:ListAllMyBuckets`
    - `s3:GetBucketAcl`
    - `s3:GetBucketPolicy`
    - `s3:PutObject`

### 4. Configure Your Bucket Name

- **Edit `lambda_function.py` and replace the bucket name**:
    ```python
    Bucket="open-aws-sentinel-reports-yourname"
    ```
- Save and re-upload if needed.

### 5. Run & Test

- In the Lambda console, click “Test” with any event (input ignored).
- Check your S3 bucket under `scan-results/` for the new JSON report.

### 6. (Optional) Scheduling

- Add a CloudWatch Events trigger (EventBridge rule) for automated daily runs:
    ```
    rate(1 day)
    ```
- Disable or delete the rule if you want to save free tier resources.


---

## License

MIT
