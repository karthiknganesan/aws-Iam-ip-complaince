# AWS IAM Group Remediation Script

## Overview

This Python script reads IAM usernames from a CSV file and adds them to the IAM group:

`PFE-Iam-IP-Restrict`

The script is designed for bulk IAM remediation and supports large AWS IAM environments.

---

# Features

- Bulk IAM group assignment
- Duplicate membership validation
- Multithreading support
- Supports 1000+ IAM users
- Retry handling for AWS API calls
- Logging with timestamps
- AWS API connection pooling
- Safe rerun support

---

# What This Script Does

The script performs the following steps:

1. Reads IAM usernames from CSV file
2. Checks whether the user already exists in:
   `PFE-Iam-IP-Restrict`
3. If already added:
   - skips the user safely
4. If not added:
   - adds the user to the IAM group
5. Displays logs for all actions

---

# CSV File Format

File Name:

```text
iam_non_compliant_users.csv
```

Example:

```csv
Username
test-user1
test-user2
devops-user
```

---

# Prerequisites

Install dependency:

```bash
pip install boto3
```

Configure AWS credentials:

```bash
aws configure
```

---

# Run Script

```bash
python iam_user_group_remediaton.py
```

---

# Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:AddUserToGroup",
    "iam:ListGroupsForUser"
  ],
  "Resource": "*"
}
```

---

# Example Output

```text
2026-05-23 13:46:08,156 [INFO] Starting IAM Group Assignment
2026-05-23 13:46:08,157 [INFO] Total Users Loaded From CSV: 11
2026-05-23 13:46:10,244 [INFO] User-001 already exists in group
2026-05-23 13:46:10,251 [INFO] user-test-1 already exists in group
2026-05-23 13:46:10,603 [INFO] Added user-terraform to PFE-IAM-IP-Restrict
2026-05-23 13:46:10,604 [INFO] Added s3-user to PFE-IAM-IP-Restrict
2026-05-23 13:46:10,608 [INFO] IAM Group Assignment Completed
```

---

# Notes

- IAM group names are case-sensitive
- CSV and script must be in same folder
- Script skips already existing users safely
- Uses multithreading for faster execution
- Recommended for bulk IAM remediation tasks
- No additional library required for CSV handling
