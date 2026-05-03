import os
from src.crypto.elgamal import SignatureHandler

def test_sign_and_verify():
    print("Test 1: Sign & Verify Valid Vault")
    handler = SignatureHandler()
    p, a, priv, pub = 467, 2, 150, pow(2, 150, 467)
    data = '{"nonce":"abc","ciphertext":"xyz","tag":"123"}'
    
    sig = handler.sign_vault(data.encode('utf-8'), priv, p, a)
    assert "r" in sig and "s" in sig
    assert handler.verify_vault(data.encode('utf-8'), sig, pub, p, a)
    print("Signature generated and verified successfully")
    return True


def test_tamper_detection():
    print("\nTest 2: Tamper Detection")
    handler = SignatureHandler()
    p, a, priv, pub = 467, 2, 150, pow(2, 150, 467)
    data = '{"nonce":"abc","ciphertext":"xyz","tag":"123"}'
    
    sig = handler.sign_vault(data.encode('utf-8'), priv, p, a) 
    tampered_data = data.replace("abc", "abd")
    assert not handler.verify_vault(tampered_data.encode('utf-8'), sig, pub, p, a)
    print("Tampered data correctly rejected")
    return True


def test_ephemeral_uniqueness():
    print("\nTest 3: Ephemeral Key Uniqueness")
    handler = SignatureHandler()
    p, a, priv, pub = 467, 2, 150, pow(2, 150, 467)
    data = '{"nonce":"abc","ciphertext":"xyz","tag":"123"}'
    
    sig1 = handler.sign_vault(data.encode('utf-8'), priv, p, a)
    sig2 = handler.sign_vault(data.encode('utf-8'), priv, p, a)
    assert sig1 != sig2
    assert handler.verify_vault(data.encode('utf-8'), sig1, pub, p, a)
    assert handler.verify_vault(data.encode('utf-8'), sig2, pub, p, a)
    print("Each signature is unique but valid")
    return True


def test_invalid_bounds():
    print("\nTest 4: Invalid Signature Bounds")
    handler = SignatureHandler()
    p, a, pub = 467, 2, pow(2, 150, 467)
    data = '{"nonce":"abc","ciphertext":"xyz","tag":"123"}'
    
    bad_sig = {"r": p + 10, "s": 5}
    assert not handler.verify_vault(data.encode('utf-8'), bad_sig, pub, p, a)
    print("Out-of-bounds signature correctly rejected")
    return True


def run_all_tests():
    print("Running Module 3 Tests: ElGamal Signatures\n")
    tests = [
        test_sign_and_verify,
        test_tamper_detection,
        test_ephemeral_uniqueness,
        test_invalid_bounds
    ]
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"FAILED: {e}")
            results.append(False)
    
    print(f"\nResults: {sum(results)}/{len(results)} tests passed")
    return all(results)


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)