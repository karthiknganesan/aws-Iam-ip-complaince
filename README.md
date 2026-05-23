# AWS IAM IP Restrict Compliance Audit

This Python script audits AWS IAM users and identifies NON-COMPLIANT users who do not have:

- IP Restrict related IAM Group
OR
- IP Restrict related IAM Policy

The script exports the final report to a CSV file.

---

# Checks Performed

The script checks for:

## IAM Groups
- IP-Restrict
- IP_Restrict
- IP Restrict
- IPRestrict

## IAM Policies
- Attached User Policies
- Inline User Policies

Matching is case-insensitive.

---

# Output

CSV Report contains:
- Username
- ARN
- Creation Date
- Groups
- Console Access
- Compliance Status

Example Output File:
```bash

iam_non_compliant_users_20260523_120000.csv
