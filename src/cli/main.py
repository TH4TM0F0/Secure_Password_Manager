from src.core.vault_manager import VaultManager
from src.crypto.elgamal.key_generation import ElgamalKeyManager
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
KEYS_DIR = BASE_DIR / "data" / "keys"


def load_public_key(username: str) -> int:
    """Load a user's public key from file for export/import."""
    pub_key_file = KEYS_DIR / f"{username}_public_key.json"
    if not pub_key_file.exists():
        raise FileNotFoundError(f"Public key not found for user: {username}")
    
    with open(pub_key_file, "r") as f:
        data = json.load(f)
    return data["public key"]


def main():
    print("Secure Password Manager - Modules 1-4")
    print("=" * 50)
    
    # Get user credentials
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
        
    master_password = input("Enter your master password: ").strip()
    if not master_password:
        print("Master password cannot be empty.")
        return
    
    # Initialize vault manager
    try:
        mgr = VaultManager(username, master_password)
    except Exception as e:
        print(f"Failed to initialize vault: {e}")
        return
    
    # Main menu loop
    while True:
        print("\nMenu:")
        print("1. Add credential")
        print("2. Retrieve credential")
        print("3. Update credential")
        print("4. Delete credential")
        print("5. Export vault to another user")
        print("6. Import vault from another user")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == "1":
            website = input("Website: ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            mgr.add(website, user, password)
            
        elif choice == "2":
            website = input("Website to retrieve: ").strip()
            mgr.retrieve(website)
            
        elif choice == "3":
            website = input("Website to update: ").strip()
            print("Leave fields blank to keep current value.")
            user = input("New username (or press Enter to keep): ").strip()
            password = input("New password (or press Enter to keep): ").strip()
            mgr.update(website, user if user else None, password if password else None)
            
        elif choice == "4":
            website = input("Website to delete: ").strip()
            mgr.delete(website)
            
        elif choice == "5":
            recipient = input("Recipient username: ").strip()
            if not recipient:
                print("Recipient username required.")
                continue
            try:
                mgr.export_vault(recipient)
                print("Export completed.")
            except Exception as e:
                print(f"Export failed: {e}")

        elif choice == "6":
            file_path = input("Path to export file: ").strip()
            sender = input("Sender username (for signature verification): ").strip()
            new_pass = input("Enter your master password: ").strip()
            if not file_path or not sender or not new_pass:
                print("All fields required.")
                continue
            try:
                mgr.import_vault(file_path, sender, new_pass)
                print("Import completed.")
            except Exception as e:
                print(f"Import failed: {e}")

        elif choice == "7":
                print("Exiting. Vault data saved.")
                break
            
        else:
            print("Invalid option. Please select 1-7.")


if __name__ == "__main__":
    main()