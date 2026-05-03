import hashlib


def sha256_hash(data_to_hash: bytes):
    '''Compute SHA-256 Hash'''
    return hashlib.sha256(data_to_hash).hexdigest()