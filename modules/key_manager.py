import os
import time
import json

class KeyManager:
    """
    A framework for managing the lifecycle of cryptographic keys, including
    generation, access, rotation, and expiration, with detailed logging.
    """

    def __init__(self):
        """Initializes the key manager with empty stores for keys and logs."""
        self.active_keys = {}
        self.archived_keys = {}
        self.usage_log = []
        print("KeyManager initialized.")

    def generate_session_key(self, owner):
        """
        Generates a new 16-byte session key for a given owner.

        Returns:
            A tuple (key_id, key_bytes) for the newly generated key.
        """
        key_bytes = os.urandom(16)
        key_id = f"sk_{owner}_{int(time.time()*1000)}"
        self.active_keys[key_id] = {
            "key": key_bytes.hex(),
            "owner": owner,
            "created_at": time.time(),
            "use_count": 0
        }
        self._log(key_id, "GENERATED", owner)
        return key_id, key_bytes

    def get_key(self, key_id):
        """
        Retrieves an active key by its ID, logs the access, and increments its use count.
        """
        if key_id not in self.active_keys:
            raise KeyError(f"Key {key_id} not found or is not active.")
        self.active_keys[key_id]["use_count"] += 1
        self._log(key_id, "ACCESSED", self.active_keys[key_id]["owner"])
        return bytes.fromhex(self.active_keys[key_id]["key"])

    def rotate_key(self, key_id):
        """
        Rotates a key: archives the old key and generates a new one for the same owner.
        
        Returns:
            A tuple (new_key_id, new_key_bytes) for the new key.
        """
        if key_id not in self.active_keys:
            raise KeyError(f"Key {key_id} not found or is not active.")
        
        # Archive the old key
        old_key_data = self.active_keys.pop(key_id)
        old_key_data["archived_at"] = time.time()
        old_key_data["reason"] = "ROTATED"
        self.archived_keys[key_id] = old_key_data
        self._log(key_id, "ROTATED", old_key_data["owner"])
        
        # Generate a new key for the same owner
        new_id, new_key = self.generate_session_key(old_key_data["owner"])
        return new_id, new_key

    def expire_key(self, key_id, reason="EXPIRED"):
        """
        Expires a specific key by moving it from the active pool to the archive.
        """
        if key_id not in self.active_keys:
            return
        
        expired_key_data = self.active_keys.pop(key_id)
        expired_key_data["archived_at"] = time.time()
        expired_key_data["reason"] = reason
        self.archived_keys[key_id] = expired_key_data
        self._log(key_id, reason, expired_key_data["owner"])

    def expire_old_keys(self, max_age_seconds=300):
        """
        Scans all active keys and expires any that are older than the specified age.
        
        Returns:
            A list of key IDs that were expired.
        """
        now = time.time()
        expired_ids = [
            key_id for key_id, key_data in self.active_keys.items()
            if now - key_data["created_at"] > max_age_seconds
        ]
        for key_id in expired_ids:
            self.expire_key(key_id)
        return expired_ids

    def _log(self, key_id, operation, owner):
        """Internal method to log a key management operation."""
        self.usage_log.append({
            "key_id": key_id,
            "operation": operation,
            "owner": owner,
            "timestamp": time.time()
        })

    def get_summary(self):
        """
        Prints a summary table of all currently active keys and returns statistics.
        """
        print(f"\n{'Key ID':<30} {'Owner':<15} {'Age(s)':<10} {'Uses':<6}")
        print("-" * 65)
        now = time.time()
        for kid, kdata in self.active_keys.items():
            age = round(now - kdata["created_at"], 1)
            print(f"{kid[:28]:<30} {kdata['owner']:<15} {age:<10.1f} {kdata['use_count']:<6}")
        
        return {
            "active_count": len(self.active_keys),
            "archived_count": len(self.archived_keys),
            "total_operations": len(self.usage_log)
        }

    def save_log(self, path):
        """Saves the detailed usage log to a JSON file."""
        # Ensure the directory exists
        dir_name = os.path.dirname(path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
            
        with open(path, "w") as f:
            json.dump(self.usage_log, f, indent=2)
        print(f"\nUsage log saved to {path}")

if __name__ == "__main__":
    # --- DEMO ---
    km = KeyManager()
    
    # 1. Generate some initial keys
    id1, k1 = km.generate_session_key("dr_alice")
    id2, k2 = km.generate_session_key("dr_bob")
    id3, k3 = km.generate_session_key("patient_john")
    
    # 2. Simulate key usage
    km.get_key(id1)
    km.get_key(id1)
    km.get_key(id2)
    
    # 3. Rotate a key
    new_id, new_key = km.rotate_key(id3)
    print(f"\nRotated key: {id3} -> {new_id}")
    
    # 4. Expire old keys (using a very short lifetime for demo purposes)
    print("\nExpiring all keys older than 0 seconds...")
    expired = km.expire_old_keys(max_age_seconds=0)
    print(f"Expired keys: {expired}")
    
    # 5. Get and print a summary of the current state
    summary = km.get_summary()
    print(f"\nActive: {summary['active_count']}, Archived: {summary['archived_count']}")
    
    # 6. Save the audit log
    km.save_log("performance_results/key_log.json")