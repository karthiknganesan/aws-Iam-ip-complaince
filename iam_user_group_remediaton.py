import boto3
import csv
import logging
from botocore.exceptions import ClientError
from botocore.config import Config
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
# Boto3 Configuration
# --------------------------------------------------
config = Config(
    retries={
        "max_attempts": 10,
        "mode": "standard"
    },
    max_pool_connections=100
)

# --------------------------------------------------
# AWS IAM Client
# --------------------------------------------------
iam = boto3.client("iam", config=config)

# --------------------------------------------------
# Constants
# --------------------------------------------------
CSV_FILE = "iam_non_compliant_users.csv"

GROUP_NAME = "PFE-Iam-IP-Restrict"

# --------------------------------------------------
# Read Users From CSV
# --------------------------------------------------
def read_users_from_csv():

    users = []

    try:

        with open(CSV_FILE, mode="r", encoding="utf-8") as file:

            reader = csv.DictReader(file)

            for row in reader:

                username = row.get("Username")

                if username:
                    users.append(username.strip())

        logger.info(f"Total Users Loaded From CSV: {len(users)}")

    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")

    return users

# --------------------------------------------------
# Check If User Already Exists In Group
# --------------------------------------------------
def user_in_group(username):

    try:

        paginator = iam.get_paginator("list_groups_for_user")

        for page in paginator.paginate(UserName=username):

            for group in page["Groups"]:

                group_name = group["GroupName"].strip().lower()

                if group_name == GROUP_NAME.strip().lower():
                    return True

    except ClientError as e:
        logger.warning(f"Unable to fetch groups for {username}: {e}")

    return False

# --------------------------------------------------
# Add User To Group
# --------------------------------------------------
def add_user_to_group(username):

    try:

        # Skip if already exists
        if user_in_group(username):

            logger.info(f"{username} already exists in group")
            return

        iam.add_user_to_group(
            GroupName=GROUP_NAME,
            UserName=username
        )

        logger.info(f"Added {username} to {GROUP_NAME}")

    except ClientError as e:
        logger.error(f"Failed to add {username}: {e}")

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():

    logger.info("Starting IAM Group Assignment")

    users = read_users_from_csv()

    if not users:
        logger.warning("No users found in CSV")
        return

    with ThreadPoolExecutor(max_workers=25) as executor:

        futures = [
            executor.submit(add_user_to_group, username)
            for username in users
        ]

        for future in as_completed(futures):

            try:
                future.result()

            except Exception as e:
                logger.error(f"Thread execution error: {e}")

    logger.info("IAM Group Assignment Completed")

# --------------------------------------------------
# Entry Point
# --------------------------------------------------
if __name__ == "__main__":
    main()