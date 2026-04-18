from enum import Enum
from dataclasses import dataclass
from typing import Optional
import bcrypt
import base64
import hashlib
import time
import hmac

# -------------------- Role Definitions --------------------
class Role(Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"

# Permission sets mapped to each role (Principle of Least Privilege)
ROLE_PERMISSIONS = {
    Role.ADMIN: {"READ", "WRITE", "EXECUTE", "SHUTDOWN", "CONFIG"},
    Role.OPERATOR: {"READ", "WRITE", "EXECUTE"},
    Role.VIEWER: {"READ"},
}

# -------------------- User Model --------------------
@dataclass
class User:
    username: str
    password_hash: bytes  # bcrypt hash stored at registration
    role: Role
    totp_secret: str      # Shared TOTP secret (base32)

# In-memory user store (replace with secure DB in production)
USER_STORE: dict[str, User] = {}

# -------------------- Registration --------------------
def register_user(username: str, plaintext_password: str,
                  role: Role, totp_secret: str) -> None:
    """Hash password with bcrypt (cost=12) and store user."""
    salt = bcrypt.gensalt(rounds=12)
    pw_hash = bcrypt.hashpw(plaintext_password.encode(), salt)
    USER_STORE[username] = User(username, pw_hash, role, totp_secret)
    print(f"[+] User '{username}' registered with role {role.value}.")

# -------------------- TOTP Generation --------------------
def _generate_totp(secret: str, interval: int = 30) -> str:
    """Simplified TOTP: HMAC-SHA256 over current time window."""
    timestamp = int(time.time() // interval)
    key = base64.b32decode(secret.upper())
    msg = timestamp.to_bytes(8, "big")

    mac = hashlib.pbkdf2_hmac("sha256", msg, key, 1)
    offset = mac[-1] & 0x0F
    code = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF

    return str(code % 10**6).zfill(6)

# -------------------- Authentication --------------------
def authenticate(username: str, plaintext_password: str,
                 provided_totp: str) -> Optional[User]:
    """
    Two-factor authentication:
    1. Verify bcrypt password hash.
    2. Verify TOTP token against current time window.
    Returns the User object on success, None on failure.
    """
    user = USER_STORE.get(username)

    if user is None:
        print("[-] Authentication failed: unknown user.")
        return None

    # Factor 1: Password verification
    if not bcrypt.checkpw(plaintext_password.encode(), user.password_hash):
        print("[-] Authentication failed: incorrect password.")
        return None

    # Factor 2: TOTP verification
    expected_totp = _generate_totp(user.totp_secret)
    if not hmac.compare_digest(expected_totp, provided_totp):
        print("[-] Authentication failed: invalid TOTP token.")
        return None

    print(f"[+] User '{username}' authenticated successfully.")
    return user

# -------------------- Authorization (RBAC) --------------------
def authorize(user: User, operation: str) -> bool:
    """
    RBAC check: verify user's role permits the requested operation.
    Logs the decision for audit purposes.
    """
    permitted = ROLE_PERMISSIONS.get(user.role, set())

    if operation in permitted:
        print(f"[+] AUTHORIZED: '{user.username}' ({user.role.value}) -> '{operation}'")
        return True
    else:
        print(f"[-] DENIED: '{user.username}' ({user.role.value}) attempted '{operation}'")
        return False

# -------------------- Demo --------------------
if __name__ == "__main__":
    # Register users
    register_user("alice", "SecurePass0123", Role.ADMIN, "JBSWY3DPEHPK3PXP")
    register_user("bob", "ViewOnly!456", Role.VIEWER, "JBSWY3DPEHPK3PXP")

    # Simulate login for ADMIN user
    totp_now = _generate_totp("JBSWY3DPEHPK3PXP")
    user = authenticate("alice", "SecurePass0123", totp_now)

    if user:
        authorize(user, "WRITE")      # Allowed
        authorize(user, "SHUTDOWN")   # Allowed

    # Simulate VIEWER attempting unauthorized operation
    user_b = authenticate("bob", "ViewOnly!456", totp_now)

    if user_b:
        authorize(user_b, "WRITE")    # Denied