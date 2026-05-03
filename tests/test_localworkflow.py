import os
import sys
import json
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.vault_manager import VaultManager
from src.crypto.elgamal.key_generation import ElgamalKeyManager


TEST_USER = "local_workflow_test"
MASTER_PASS = "SecureMasterPass123!"
DATA_DIR = PROJECT_ROOT / "data"

def _setup_environment():
    """Clean previous test data to guarantee idempotent runs."""
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print("Test environment prepared.")

def _header(title: str):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")

def _test(num: int, name: str):
    print(f"\nTest {num}: {name}")

def _assert(cond: bool, success_msg: str, fail_msg: str = ""):
    if not cond:
        raise AssertionError(fail_msg or success_msg)
    print(f"{success_msg}")

# =============================================================================
# TEST SUITE
# =============================================================================

def test_module1_key_lifecycle():
    _test(1, "ElGamal Key Generation & Persistence")
    km = ElgamalKeyManager(TEST_USER)
    km.generate_keys()
    
    _assert(km.p and km.a, "- Parameters loaded/generated")
    _assert(km.public_key and km.private_key, "- Key pair generated")
    _assert((DATA_DIR / "keys" / f"{TEST_USER}_private_key.json").exists(), "- Private key file saved")
    _assert((DATA_DIR / "keys" / f"{TEST_USER}_public_key.json").exists(), "- Public key file saved")
    return True

def test_module2_vault_crud():
    _test(2, "Vault CRUD Operations & JSON Structure")
    mgr = VaultManager(TEST_USER, MASTER_PASS)
    vault_file = DATA_DIR / "vaults" / f"{TEST_USER}_vault.json"

    # Add
    mgr.add("github.com", "alice_dev", "GitP@ss!")
    _assert(vault_file.exists(), "- Vault file created after first add")
    
    # Structure check
    with open(vault_file) as f:
        data = json.load(f)
    _assert(all(k in data for k in ["nonce", "ciphertext", "tag", "signature"]), 
            "- JSON matches spec: {nonce, ciphertext, tag, signature}")

    # Retrieve
    res = mgr.vault.retrieve_credential("github.com")
    _assert(isinstance(res, dict) and res["username"] == "alice_dev", 
            "- Credential retrieved correctly")

    # Update
    mgr.update("github.com", password="N3w_Git_P@ss!")
    res = mgr.vault.retrieve_credential("github.com")
    _assert(res["password"] == "N3w_Git_P@ss!", 
            "- Credential updated & vault re-signed")

    # Add second & Delete
    mgr.add("bank.com", "alice_bank", "B@nk!ng123")
    mgr.delete("bank.com")
    res = mgr.vault.retrieve_credential("bank.com")
    _assert(res == "Credential not found.", 
            "- Credential deleted & vault re-signed")
    return True

def test_persistence_across_sessions():
    _test(3, "Vault Persistence & Session Reload")
    # Simulate fresh app launch with same credentials
    mgr = VaultManager(TEST_USER, MASTER_PASS)
    res = mgr.vault.retrieve_credential("github.com")
    _assert(isinstance(res, dict) and res["password"] == "N3w_Git_P@ss!", 
            "- Vault loaded, verified & decrypted in new session")
    return True

def test_tamper_detection():
    _test(4, "Module 3: Signature Verification & Tamper Detection")
    vault_file = DATA_DIR / "vaults" / f"{TEST_USER}_vault.json"
    with open(vault_file) as f:
        original = json.load(f)

    try:
        # Flip last character of ciphertext to simulate tampering
        tampered = original.copy()
        tampered["ciphertext"] = tampered["ciphertext"][:-1] + ("Z" if tampered["ciphertext"][-1] != "Z" else "A")
        with open(vault_file, "w") as f:
            json.dump(tampered, f, indent=4)

        mgr = VaultManager(TEST_USER, MASTER_PASS)
        mgr.vault.retrieve_credential("github.com")  # Should trigger verification failure
        print("- FAILED: Tampered vault was incorrectly accepted!")
        return False
    except ValueError as e:
        msg = str(e).lower()
        if any(kw in msg for kw in ["integrity", "verify", "tampered", "failed"]):
            print("- Single-bit tamper correctly rejected (signature mismatch)")
            return True
        print(f"- FAILED: Unexpected error: {e}")
        return False
    finally:
        # Restore original file
        with open(vault_file, "w") as f:
            json.dump(original, f, indent=4)

def test_wrong_master_password():
    _test(5, "Module 2: Wrong Master Password Handling")
    try:
        mgr = VaultManager(TEST_USER, "WrongPassword123!")
        mgr.vault.retrieve_credential("github.com")
        print("- FAILED: Wrong password incorrectly granted access!")
        return False
    except ValueError as e:
        msg = str(e).lower()
        if any(kw in msg for kw in ["password", "decrypt", "auth", "failed"]):
            print("- Wrong master password correctly rejected (AES-GCM auth failure)")
            return True
        print(f"- FAILED: Unexpected error: {e}")
        return False

# =============================================================================
# RUNNER
# =============================================================================

def run_all_tests():
    _header("Local Workflow Integration Tests (Modules 1 + 2 + 3)")
    _setup_environment()
    
    tests = [
        test_module1_key_lifecycle,
        test_module2_vault_crud,
        test_persistence_across_sessions,
        test_tamper_detection,
        test_wrong_master_password
    ]
    
    results = []
    for test_func in tests:
        try:
            results.append(test_func())
        except Exception as e:
            print(f"CRASH: {e}")
            results.append(False)
            
    _header("Test Summary")
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("Modules 1-3 fully integrated & spec-compliant!")
    else:
        print("Some tests failed. Review output above.")
    print(f"{'='*65}\n")
    return all(results)

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)