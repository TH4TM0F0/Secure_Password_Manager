from pathlib import Path
from typing import Optional
from src.crypto.aes.credential import Credential
from src.crypto.hashing.sha256 import sha256_hash
from src.crypto.elgamal import SignatureHandler
from Crypto.Cipher import AES
import base64
import json


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
VAULT_DIR = BASE_DIR / "data" / "vaults"


class Vault:
    def __init__(self, username: str, master_password: str, public_key : int, private_key : int, p: int, a: int):
        self.__username = username
        self.__vault_dir = VAULT_DIR
        self.__dict_vaults_file = self.__vault_dir / f"{username}_vault.json"
        self.__credentials = dict()
        self.__signature = None
        self.__aes_key = bytes.fromhex(sha256_hash(master_password.encode()))
        self.__signature_handler = SignatureHandler()
        self.__public_key = public_key
        self.__private_key = private_key
        self.__p = p
        self.__a = a


    def add_credential(self, credential: Credential):
        self.load_and_verify()
        credential_json = credential.to_dict()
        self.__credentials[credential.website] = credential_json[credential.website]
        self.sign_and_save()


    def retrieve_credential(self, website: str) -> Optional[dict | str]:
        self.load_and_verify()
        return self.__credentials.get(website, "Credential not found.")


    def update_credential(self, credential: Credential) -> bool:
        # TODO: when implementing the controller check 
        # if the user wishes to update 
        # the username or the password or both and then update accordingly
        self.load_and_verify()
        if self.__has_credential(credential.website):
            self.__credentials[credential.website] = credential.to_dict()[credential.website]
            self.sign_and_save()
            return True
        return False


    def delete_credential(self, website: str) -> bool:
        self.load_and_verify()
        if self.__has_credential(website):
            del self.__credentials[website]
            self.sign_and_save()
            return True
        return False


    def __has_credential(self, website: str) -> bool:
        return website in self.__credentials.keys()


    def __encrypt_vault(self):
        cipher = AES.new(self.__aes_key, AES.MODE_GCM)
        json_data = json.dumps(self.__credentials , sort_keys = True).encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(json_data)
        nonce = cipher.nonce
        return (nonce, ciphertext, tag)


    def __decrypt_vault(self , nonce: bytes, ciphertext: bytes, tag: bytes):
        cipher = AES.new(self.__aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Decryption failed: Wrong master password or vault has been tampered with.")
        plaintext = plaintext.decode('utf-8')
        self.__credentials = json.loads(plaintext)


    def sign_and_save(self):
        (nonce , ciphertext, tag) = self.__encrypt_vault()
        encrypted_data = nonce + ciphertext + tag
        self.__signature = self.__signature_handler.sign_vault(encrypted_data, self.__private_key, self.__p, self.__a) 
        self.__vault_dir.mkdir(parents = True, exist_ok = True)
        with open(self.__dict_vaults_file, "w") as file:
            json.dump({
                "nonce" : base64.b64encode(nonce).decode('utf-8'),
                "ciphertext" : base64.b64encode(ciphertext).decode('utf-8'),
                "tag" : base64.b64encode(tag).decode('utf-8'),
                "signature" : self.__signature
            }, file, indent = 4)


    def load_and_verify(self):
        if not self.__dict_vaults_file.exists():
            self.__credentials = {}
        else:
            try:
                with open(self.__dict_vaults_file, "r") as file:
                    data = json.load(file)
                nonce = base64.b64decode(data["nonce"])
                ciphertext = base64.b64decode(data["ciphertext"])
                tag = base64.b64decode(data["tag"])
                encrypted_data = nonce + ciphertext + tag
                if not self.__signature_handler.verify_vault(encrypted_data, data["signature"], self.__public_key, self.__p, self.__a):
                    raise ValueError("Signature verification failed: Vault integrity compromised.")
                self.__signature = data["signature"]
                self.__decrypt_vault(nonce, ciphertext, tag)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                raise ValueError(f"Failed to load vault: {str(e)}")