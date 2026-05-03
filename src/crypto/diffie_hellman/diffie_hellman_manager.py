from pathlib import Path
from src.crypto.hashing.sha256 import sha256_hash
from src.crypto.diffie_hellman.params import create_diffie_hellman_config_file
import json
import secrets
import hashlib


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
Diffie_Hellman_CONFIG_FILE = BASE_DIR / "data" / "config" / "diffie_hellman_params.json"


class DiffieHellmanManager:
    def __init__(self):
        self.__config_file = Diffie_Hellman_CONFIG_FILE
        self.__q = None
        self.__alpha = None
        self.__private_key = None
        self.__public_key = None
        self._load_params()

    def _load_params(self):
        """Load shared DH parameters (q, a) from config file."""
        if not self.__config_file.exists():
            create_diffie_hellman_config_file()
        
        with open(self.__config_file, "r") as file:
            params = json.load(file)
            
        self.__q = params.get("q")
        self.__alpha = params.get("alpha")
        
        if self.__q is None or self.__alpha is None:
            raise ValueError("Diffie-Hellman config must contain 'q' (prime) and 'alpha' (primitive root)")

    @property
    def q(self):
        return self.__q

    @property
    def alpha(self):
        return self.__alpha

    @property
    def private_key(self):
        return self.__private_key

    @property
    def public_key(self):
        return self.__public_key

    def generate_keypair(self):
        """
        Generates an ephemeral DH key pair.
        Private key range: [2, q-2]
        Returns nothing; sets __private_key and __public_key internally.
        """
        self.__private_key = secrets.randbelow(self.__q - 3) + 2
        self.__public_key = pow(self.__alpha, self.__private_key, self.__q)

    def compute_shared_secret(self, other_public: int) -> int:
        """
        Computes the shared secret using other party's public key and own private key.
        Formula: shared = other_public^own_private mod q
        """
        if self.__private_key is None:
            raise ValueError("Private key not generated. Call generate_keypair() first.")
        return pow(other_public, self.__private_key, self.__q)

    def derive_session_key(self, shared_secret: int) -> bytes:
        """
        Derives a 32-byte AES-256 session key from the shared secret.
        Uses SHA-256 over the byte representation of the integer.
        Returns raw bytes (32 bytes), NOT hex string.
        """
        byte_length = (shared_secret.bit_length() + 7) // 8
        shared_bytes = shared_secret.to_bytes(byte_length, byteorder="big")
        
        return hashlib.sha256(shared_bytes).digest()
    
    def set_private_key(self, private_key: int):
        """Set the DH private key (used during Import to load previously generated key)."""
        self.__private_key = private_key