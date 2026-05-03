from src.crypto.aes.credential import Credential
from src.crypto.aes.vault import Vault
from src.crypto.elgamal import ElgamalKeyManager
from src.crypto.diffie_hellman.diffie_hellman_manager import DiffieHellmanManager
from src.crypto.elgamal.signature_handler import SignatureHandler
from src.crypto.hashing.sha256 import sha256_hash
from pathlib import Path
from datetime import datetime
from Crypto.Cipher import AES
import json
import base64   


BASE_DIR = Path(__file__).resolve().parent.parent.parent
KEY_DIR = BASE_DIR / "data" / "keys"


class VaultManager:
    def __init__(self, username: str, master_password: str):
        self.username = username
        self.key_manager = ElgamalKeyManager(username)
        self.key_manager.generate_keys() 
        self.p = self.key_manager.p
        self.a = self.key_manager.a
        self.private_key = self.key_manager.private_key
        self.public_key = self.key_manager.public_key
        self.vault = Vault(
            username=username,
            master_password=master_password,
            public_key=self.public_key,
            private_key=self.private_key,
            p=self.p,
            a=self.a
        )
        self.__sig_handler = SignatureHandler()
        self.__setup_dh_keys()


    def add(self, website: str, username: str, password: str) -> None:
        if not all([website, username, password]):
            print("All fields (website, username, password) are required.")
            return

        try:
            credential = Credential(website, username, password)
            self.vault.add_credential(credential)
            print(f"Added credential for {website} & re-signed vault.")
        except ValueError as e:
            print(f"{e}")


    def retrieve(self, website: str) -> None:
        try:
            result = self.vault.retrieve_credential(website)
            if isinstance(result, dict):
                print(f"Found credential for {website}:")
                print(f"Username: {result['username']}")
                print(f"Password: {result['password']}")
            else:
                print(f"{result}")
        except ValueError as e:
            print(f"{e}")

    def update(self, website: str, username: str = None, password: str = None) -> None:
        try:
            current = self.vault.retrieve_credential(website)
            if isinstance(current, str):
                print(f"{current}")
                return

            new_user = username if username is not None else current["username"]
            new_pass = password if password is not None else current["password"]

            credential = Credential(website, new_user, new_pass)
            self.vault.update_credential(credential)
            print(f"Updated credential for {website} & re-signed vault.")
        except ValueError as e:
            print(f"{e}")

    def delete(self, website: str) -> None:
        try:
            if self.vault.delete_credential(website):
                print(f"Deleted {website} & re-signed vault.")
            else:
                print(f"{website} not found in vault.")
        except ValueError as e:
            print(f"{e}")


    def export_vault(self, recipient_username: str) -> dict:
        try:
            recipient_dh_file = KEY_DIR / f"{recipient_username}_dh_public.json"
            if not recipient_dh_file.exists():
                raise FileNotFoundError(f"Recipient '{recipient_username}' has not initialized DH keys. Ask them to open the app first.")
            
            with open(recipient_dh_file, "r") as f:
                rec_dh_data = json.load(f)
                
            recipient_elgamal_pub_file = KEY_DIR / f"{recipient_username}_public_key.json"
            if not recipient_elgamal_pub_file.exists():
                raise FileNotFoundError(f"Recipient's ElGamal public key not found: {recipient_username}")
            with open(recipient_elgamal_pub_file, "r") as f:
                recipient_elgamal_pub = json.load(f)["public key"]

            rec_dh_pub_bytes = rec_dh_data["dh_public_key"].to_bytes(
                (rec_dh_data["dh_public_key"].bit_length() + 7) // 8, 'big'
            )
            if not self.__sig_handler.verify_vault(
                rec_dh_pub_bytes,
                rec_dh_data["dh_signature"],
                recipient_elgamal_pub,  
                self.p,
                self.a
            ):
                raise ValueError("Export aborted: Recipient's DH public key signature invalid.")
            
            dh = DiffieHellmanManager()
            dh.generate_keypair()
            
            shared_secret = dh.compute_shared_secret(rec_dh_data["dh_public_key"])
            session_key = dh.derive_session_key(shared_secret)
            
            self.vault.load_and_verify()
            plaintext_vault = json.dumps(self.vault._Vault__credentials, sort_keys = True).encode('utf-8')
            
            cipher = AES.new(session_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext_vault)
            nonce = cipher.nonce
            
            encrypted_data = nonce + ciphertext + tag
            vault_signature = self.__sig_handler.sign_vault(encrypted_data, self.private_key, self.p, self.a)
            
            sender_dh_pub_bytes = dh.public_key.to_bytes((dh.public_key.bit_length() + 7) // 8, 'big')
            sender_dh_sig = self.__sig_handler.sign_vault(sender_dh_pub_bytes, self.private_key, self.p, self.a)
            
            export_package = {
                "sender_username": self.username,
                "recipient_username": recipient_username,
                "sender_dh_public_key": dh.public_key,
                "sender_dh_signature": sender_dh_sig,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "vault_signature": vault_signature,
                "timestamp": str(datetime.now().isoformat())
            }
            
            EXPORTS_DIR = BASE_DIR / "data" / "exports"
            EXPORTS_DIR.mkdir(parents = True, exist_ok = True)
            export_file = EXPORTS_DIR / f"{self.username}_to_{recipient_username}_export.json"
            with open(export_file, "w") as f:
                json.dump(export_package, f, indent = 4, sort_keys = True)
            print(f"Export package saved to: {export_file}")
            return export_package
            
        except FileNotFoundError as e:
            print(f"{e}")
            raise
        except ValueError as e:
            print(f"{e}")
            raise


    def import_vault(self, export_file_path: str, sender_username: str, new_master_password: str) -> None:
        try:
            priv_file = KEY_DIR / f"{self.username}_dh_private.json"
            if not priv_file.exists():
                raise FileNotFoundError("DH keys not found. Please initialize the app first.")
            with open(priv_file, "r") as f:
                own_dh_priv = json.load(f)["dh_private_key"]

            with open(export_file_path, "r") as f:
                export_package = json.load(f)

            sender_elgamal_pub_file = KEY_DIR / f"{sender_username}_public_key.json"
            if not sender_elgamal_pub_file.exists():
                raise FileNotFoundError(f"Sender's ElGamal public key not found: {sender_username}")
            with open(sender_elgamal_pub_file, "r") as f:
                sender_elgamal_pub = json.load(f)["public key"]

            sender_dh_pub_bytes = export_package["sender_dh_public_key"].to_bytes(
                (export_package["sender_dh_public_key"].bit_length() + 7) // 8, 'big'
            )
            if not self.__sig_handler.verify_vault(
                sender_dh_pub_bytes,
                export_package["sender_dh_signature"],
                sender_elgamal_pub, 
                self.p,
                self.a
            ):
                raise ValueError("Import aborted: Sender's DH public key signature invalid.")

            dh = DiffieHellmanManager()
            dh.set_private_key(own_dh_priv)
            shared_secret = dh.compute_shared_secret(export_package["sender_dh_public_key"])
            session_key = dh.derive_session_key(shared_secret)
            
            nonce = base64.b64decode(export_package["nonce"])
            ciphertext = base64.b64decode(export_package["ciphertext"])
            tag = base64.b64decode(export_package["tag"])
            encrypted_data = nonce + ciphertext + tag

            if not self.__sig_handler.verify_vault(
                encrypted_data,
                export_package["vault_signature"],
                sender_elgamal_pub,  
                self.p,
                self.a
            ):
                raise ValueError("Import aborted: Vault signature verification failed.")

            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            new_aes_key = bytes.fromhex(sha256_hash(new_master_password.encode()))
            cipher_new = AES.new(new_aes_key, AES.MODE_GCM)
            new_ciphertext, new_tag = cipher_new.encrypt_and_digest(plaintext)
            new_nonce = cipher_new.nonce

            new_encrypted_data = new_nonce + new_ciphertext + new_tag
            new_signature = self.__sig_handler.sign_vault(new_encrypted_data, self.private_key, self.p, self.a)
            
            vault_file = self.vault._Vault__vault_dir / f"{self.username}_vault.json"
            self.vault._Vault__vault_dir.mkdir(parents=True, exist_ok=True)
            with open(vault_file, "w") as file:
                json.dump({
                    "nonce": base64.b64encode(new_nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(new_ciphertext).decode('utf-8'),
                    "tag": base64.b64encode(new_tag).decode('utf-8'),
                    "signature": new_signature
                }, file, indent=4, sort_keys=True)

            self.vault._Vault__credentials = json.loads(plaintext.decode('utf-8'))
            print("Vault imported successfully.")

        except FileNotFoundError as e:
            print(f"{e}")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Invalid export package: {e}")
        except ValueError as e:
            print(f"{e}")
            raise
        except Exception as e:
            print(f"Import failed: {e}")
            raise


    def prepare_dh_transfer(self) -> None:
        """Generates DH keys for the current user to share with a sender."""
        try:
            dh = DiffieHellmanManager()
            dh.generate_keypair()
            
            dh_pub_bytes = dh.public_key.to_bytes((dh.public_key.bit_length() + 7) // 8, 'big')
            dh_sig = self.__sig_handler.sign_vault(dh_pub_bytes, self.private_key, self.p, self.a)
            
            pub_file = KEY_DIR / f"{self.username}_dh_public.json"
            with open(pub_file, "w") as file:
                json.dump({
                    "username": self.username,
                    "dh_public_key": dh.public_key,
                    "dh_signature": dh_sig
                }, file, indent=4)
                
            priv_file = KEY_DIR / f"{self.username}_dh_private.json"
            with open(priv_file, "w") as file:
                json.dump({
                    "dh_private_key": dh.private_key
                    }, file, indent=4)
            print(f"DH keys generated and saved to {KEY_DIR}")
        except Exception as e:
            print(f"Failed to prepare DH keys: {e}")
            raise


    def __setup_dh_keys(self):
        """Auto-generate and save DH keys during initialization. Simulates background key exchange."""
        pub_file = KEY_DIR / f"{self.username}_dh_public.json"
        priv_file = KEY_DIR / f"{self.username}_dh_private.json"
        

        if pub_file.exists() and priv_file.exists():
            return
            
        dh = DiffieHellmanManager()
        dh.generate_keypair()
        
        priv_file.parent.mkdir(parents=True, exist_ok=True)
        with open(priv_file, "w") as f:
            json.dump({"dh_private_key": dh.private_key}, f)
            
        dh_pub_bytes = dh.public_key.to_bytes((dh.public_key.bit_length() + 7) // 8, 'big')
        dh_sig = self.__sig_handler.sign_vault(dh_pub_bytes, self.private_key, self.p, self.a)
        with open(pub_file, "w") as f:
            json.dump({
                "username": self.username,
                "dh_public_key": dh.public_key,
                "dh_signature": dh_sig
            }, f, indent=4)