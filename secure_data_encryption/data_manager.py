import json
import os
from typing import Dict, Optional
from cryptography.fernet import Fernet
from datetime import datetime

class DataManager:
    def __init__(self):
        self.data_file = "encrypted_data.json"
        self.encryption_key = self._load_or_create_key()
        self.cipher = Fernet(self.encryption_key)
        self.data = self._load_data()

    def _load_or_create_key(self) -> bytes:
        """Load existing key or create a new one."""
        key_file = "encryption.key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def _load_data(self) -> Dict:
        """Load encrypted data from JSON file."""
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_data(self):
        """Save encrypted data to JSON file."""
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f)

    def store_data(self, username: str, data_id: str, encrypted_data: Dict):
        """Store encrypted data for a user."""
        if username not in self.data:
            self.data[username] = {}
        
        self.data[username][data_id] = {
            "encrypted_text": encrypted_data["encrypted_text"],
            "passkey": encrypted_data["passkey"],
            "created_at": datetime.now().isoformat()
        }
        self._save_data()

    def get_data(self, username: str, data_id: str) -> Optional[Dict]:
        """Retrieve encrypted data for a user."""
        return self.data.get(username, {}).get(data_id)

    def get_user_data_ids(self, username: str) -> list:
        """Get all data IDs for a user."""
        return list(self.data.get(username, {}).keys())

    def delete_data(self, username: str, data_id: str) -> bool:
        """Delete data for a user."""
        if username in self.data and data_id in self.data[username]:
            del self.data[username][data_id]
            if not self.data[username]:
                del self.data[username]
            self._save_data()
            return True
        return False 