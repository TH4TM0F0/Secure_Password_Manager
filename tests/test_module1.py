from pathlib import Path
from src.crypto.elgamal.key_generation import ElgamalKeyManager
import json


def test_module1():
    username = "test_user"
    mgr = ElgamalKeyManager(username)
    mgr.generate_keys()
    
    # Verify files exist
    assert Path(f"data/keys/{username}_private_key.json").exists()
    assert Path(f"data/keys/{username}_public_key.json").exists()
    
    # Verify reuse
    mgr2 = ElgamalKeyManager(username)
    mgr2.generate_keys()  # Should load existing, not regenerate
    assert mgr2.private_key == mgr.private_key
    assert mgr2.public_key == mgr.public_key
    
    # Verify public key contains username
    with open(f"data/keys/{username}_public_key.json") as f:
        pub_data = json.load(f)
    assert pub_data["username"] == username
    
    print("Module 1: All checks passed")

if __name__ == "__main__":
    test_module1()