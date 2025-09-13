#!/usr/bin/env python3
"""Reset or set the admin user's password for PyGuard.

This script must be run as root. It derives the shared JWT secret by calling
ensure_secret_jwt() and updates (or creates) /etc/pyguard/users.json with a new
encrypted password hash for the 'admin' user.

Usage:
    sudo python3 scripts/reset-admin.py              # interactive prompt
    sudo python3 scripts/reset-admin.py NewPassword  # non-interactive

It adjusts sys.path so it can be launched from any directory.
"""

import json
import sys
import bcrypt
import os

import pathlib

# Ensure project root (parent of this file's directory) is on sys.path so that
# 'import pyguard' works even when invoking the script directly.
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from pyguard import ensure_secret_jwt, ensure_root, BASE_DATA_DIR


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored_hash.encode())


def main():
    ensure_root()
    ensure_secret_jwt()
    key = os.environ["JWT_SECRET_KEY"]

    if not key:
        print("JWT_SECRET_KEY environment variable is not set.")
        sys.exit(1)

    if len(sys.argv) < 2:
        new_password = input("Enter new admin password: ")
    else:
        new_password = sys.argv[1]

    encrypted_password = hash_password(new_password)
    print(f"Encrypted password: {encrypted_password}")

    DEFAULT_DICT = {
        "admin_users": [
            {
                "username": "admin",
                "password_hash": f"{encrypted_password}",
            }
        ]
    }

    users_path = os.path.join(BASE_DATA_DIR, "users.json")
    if not os.path.exists(users_path):

        with open(users_path, "w") as f:
            f.write(json.dumps(DEFAULT_DICT, indent=4))
    else:

        with open(users_path, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(
                    "Error: users.json is not a valid JSON file. Overwriting with default."
                )
                data = DEFAULT_DICT

        if "admin_users" not in data:
            data["admin_users"] = []

        found = False
        for user in data.get("admin_users", []):
            if user.get("username") == "admin":
                user["password_hash"] = encrypted_password
                found = True
                break

        if not found:
            data["admin_users"].append(
                {
                    "username": "admin",
                    "password_hash": encrypted_password,
                }
            )

        with open(users_path, "w") as f:
            f.write(json.dumps(data, indent=4))


if __name__ == "__main__":
    main()
