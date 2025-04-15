import json
import os
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from jose import jwt
from typing import Dict, Optional, Tuple

# Constants
SECRET_KEY = os.urandom(32).hex()  # In production, use a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
LOCKOUT_DURATION_MINUTES = 15
MAX_FAILED_ATTEMPTS = 3

class AuthManager:
    def __init__(self):
        self.users_file = "users.json"
        self.lockouts: Dict[str, Tuple[int, datetime]] = {}
        self._load_users()

    def _load_users(self):
        """Load users from JSON file."""
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}
            self._save_users()

    def _save_users(self):
        """Save users to JSON file."""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def _hash_password(self, password: str) -> str:
        """Hash password using PBKDF2."""
        return pbkdf2_sha256.hash(password)

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return pbkdf2_sha256.verify(password, hashed)

    def _is_locked_out(self, username: str) -> bool:
        """Check if user is locked out."""
        if username in self.lockouts:
            attempts, lockout_time = self.lockouts[username]
            if attempts >= MAX_FAILED_ATTEMPTS:
                if datetime.now() - lockout_time < timedelta(minutes=LOCKOUT_DURATION_MINUTES):
                    return True
                else:
                    # Reset lockout after duration
                    self.lockouts[username] = (0, datetime.now())
        return False

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user."""
        if username in self.users:
            return False
        
        self.users[username] = {
            "password": self._hash_password(password),
            "created_at": datetime.now().isoformat()
        }
        self._save_users()
        return True

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user and return (success, message)."""
        if self._is_locked_out(username):
            return False, f"Account locked. Try again in {LOCKOUT_DURATION_MINUTES} minutes."

        if username not in self.users:
            return False, "User not found."

        if not self._verify_password(password, self.users[username]["password"]):
            # Update failed attempts
            attempts, _ = self.lockouts.get(username, (0, datetime.now()))
            self.lockouts[username] = (attempts + 1, datetime.now())
            remaining = MAX_FAILED_ATTEMPTS - (attempts + 1)
            return False, f"Invalid password. {remaining} attempts remaining."

        # Reset failed attempts on successful login
        self.lockouts[username] = (0, datetime.now())
        return True, "Login successful"

    def create_access_token(self, username: str) -> str:
        """Create JWT access token."""
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": username,
            "exp": expire
        }
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def verify_token(self, token: str) -> Optional[str]:
        """Verify JWT token and return username if valid."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload.get("sub")
        except:
            return None
