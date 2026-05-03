from src.crypto.hashing.sha256 import sha256_hash
import math
import secrets


class SignatureHandler:
    def sign_vault(self, encrypted_vault : bytes, private_key: int, p: int, a: int) -> dict:
        hash_value = int(sha256_hash(encrypted_vault), 16)

        while True:
            k = secrets.randbelow(p - 2) + 2  
            if math.gcd(k, p - 1) == 1:
                break

        r = pow(a, k, p)
        k_inv = pow(k, -1, p - 1)
        s = (k_inv * (hash_value - private_key * r)) % (p - 1)
        return {"r": r, "s": s}


    def verify_vault(self, encrypted_vault : bytes, signature: dict, public_key: int, p: int, a: int) -> bool:
        hash_value = int(sha256_hash(encrypted_vault), 16)
        r, s = signature.get("r"), signature.get("s")

        if r is None or s is None or not (0 < r < p) or not (0 <= s < p - 1):
            return False

        v1 = pow(a, hash_value, p)
        v2 = (pow(public_key, r, p) * pow(r, s, p)) % p
        return v1 == v2