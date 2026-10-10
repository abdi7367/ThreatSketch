"""Password check for the sample app (test fixture)."""
import hashlib
import os

ADMIN_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")


def check_password(username: str, password: str) -> bool:
    digest = hashlib.sha256(password.encode()).hexdigest()
    return username == "admin" and digest == ADMIN_HASH
