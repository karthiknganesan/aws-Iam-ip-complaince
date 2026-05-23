import boto3
import csv
import logging
from datetime import datetime
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------------------------------
# Logging Configuration
# --------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# --------------------------------------------------
# AWS IAM Client
# --------------------------------------------------
iam = boto3.client("iam")

# --------------------------------------------------
# Constants
# --------------------------------------------------
CSV_FILE = f"iam_non_compliant_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# Case-insensitive keywords
KEYWORDS = [
    "ip-restrict",
    "ip_restrict",
    "ip restrict",
    "iprestrict"
]

# --------------------------------------------------
# Helper Function
# --------------------------------------------------
def contains_ip_restrict(name):

    if not name:
        return False

    name = name.lower()

    return any(keyword in name for keyword in KEYWORDS)

# --------------------------------------------------
# Fetch All IAM Users
# --------------------------------------------------
def get_all_users():

    users = []

    try:
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            users.extend(page["Users"])

        logger.info(f"Total IAM Users Found: {len(users)}")

    except ClientError as e:
        logger.error(f"Unable to fetch IAM users: {e}")

    return users

# --------------------------------------------------
# Check User Groups
# --------------------------------------------------
def user_has_ip_group(username):

    try:
        response = iam.list_groups_for_user(UserName=username)

        for group in response["Groups"]:

            if contains_ip_restrict(group["GroupName"]):
                return True

    except ClientError as e:
        logger.warning(f"Unable to fetch groups for {username}: {e}")

    return False

# --------------------------------------------------
# Check Attached Policies
# --------------------------------------------------
def user_has_attached_policy(username):

    try:
        paginator = iam.get_paginator("list_attached_user_policies")

        for page in paginator.paginate(UserName=username):

            for policy in page["AttachedPolicies"]:

                if contains_ip_restrict(policy["PolicyName"]):
                    return True

    except ClientError as e:
        logger.warning(f"Unable to fetch attached policies for {username}: {e}")

    return False

# --------------------------------------------------
# Check Inline Policies
# --------------------------------------------------
def user_has_inline_policy(username):

    try:
        paginator = iam.get_paginator("list_user_policies")

        for page in paginator.paginate(UserName=username):

            for policy in page["PolicyNames"]:

                if contains_ip_restrict(policy):
                    return True

    except ClientError as e:
        logger.warning(f"Unable to fetch inline policies for {username}: {e}")

    return False

# --------------------------------------------------
# Check Console Access
# --------------------------------------------------
def has_console_access(username):

    try:
        iam.get_login_profile(UserName=username)
        return "Enabled"

    except iam.exceptions.NoSuchEntityException:
        return "Disabled"

    except ClientError:
        return "Unknown"

# --------------------------------------------------
# Get User Groups
# --------------------------------------------------
def get_user_groups(username):

    try:
        response = iam.list_groups_for_user(UserName=username)

        groups = [group["GroupName"] for group in response["Groups"]]

        return ", ".join(groups)

    except ClientError:
        return "N/A"

# --------------------------------------------------
# Process Single User
# --------------------------------------------------
def process_user(user):

    username = user["UserName"]

    logger.info(f"Checking user: {username}")

    has_group = user_has_ip_group(username)
    has_attached_policy = user_has_attached_policy(username)
    has_inline_policy = user_has_inline_policy(username)

    # NON-COMPLIANT
    if not any([has_group, has_attached_policy, has_inline_policy]):

        return {
            "Username": username,
            "ARN": user["Arn"],
            "CreationDate": str(user["CreateDate"]),
            "Groups": get_user_groups(username),
            "ConsoleAccess": has_console_access(username),
            "ComplianceStatus": "NON-COMPLIANT"
        }

    return None

# --------------------------------------------------
# Audit Users
# --------------------------------------------------
def audit_users():

    non_compliant_users = []

    users = get_all_users()

    with ThreadPoolExecutor(max_workers=15) as executor:

        futures = [executor.submit(process_user, user) for user in users]

        for future in as_completed(futures):

            try:
                result = future.result()

                if result:
                    non_compliant_users.append(result)

            except Exception as e:
                logger.error(f"Thread execution error: {e}")

    return non_compliant_users

# --------------------------------------------------
# Export CSV
# --------------------------------------------------
def export_csv(data):

    if not data:
        logger.info("No non-compliant users found.")
        return

    headers = [
        "Username",
        "ARN",
        "CreationDate",
        "Groups",
        "ConsoleAccess",
        "ComplianceStatus"
    ]

    try:
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:

            writer = csv.DictWriter(file, fieldnames=headers)

            writer.writeheader()
            writer.writerows(data)

        logger.info(f"CSV Report Generated: {CSV_FILE}")

    except Exception as e:
        logger.error(f"Error writing CSV: {e}")

# --------------------------------------------------
# Display Results
# --------------------------------------------------
def display_results(data):

    print("\n========== NON-COMPLIANT IAM USERS ==========\n")

    if not data:
        print("No non-compliant users found.")
        return

    for user in data:

        print(f"Username          : {user['Username']}")
        print(f"ARN               : {user['ARN']}")
        print(f"Creation Date     : {user['CreationDate']}")
        print(f"Groups            : {user['Groups']}")
        print(f"Console Access    : {user['ConsoleAccess']}")
        print(f"Compliance Status : {user['ComplianceStatus']}")
        print("------------------------------------------------")

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():

    logger.info("Starting IAM Compliance Audit")

    results = audit_users()

    display_results(results)

    export_csv(results)

    logger.info("Audit Completed Successfully")

# --------------------------------------------------
# Entry Point
# --------------------------------------------------
if __name__ == "__main__":
    main()