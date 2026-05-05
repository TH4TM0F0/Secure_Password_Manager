# 🔐 Secure Password Manager + CTF Challenges
**Cairo University — Computer Engineering Dept. — CMPS426 Security Course Project**

A command-line/graphical-user-interface password manager implementing AES-GCM encryption, SHA-256 hashing, ElGamal digital signatures, and Diffie-Hellman key exchange — all built from scratch per course specifications.

---

## ✨ Features

### Module 1: ElGamal Key Management
- Generates ElGamal key pairs from scratch using shared parameters (`p`, `α`)
- Private keys stored locally with OS-level permissions (`icacls` on Windows)
- Public keys exportable for signature verification by other users

### Module 2: Vault Encryption & Credential Management
- Master password → SHA-256 → AES-256-GCM data key
- CRUD operations (add/retrieve/update/delete) with full vault re-encryption on every change
- Vault stored as pretty-printed JSON: `{"nonce", "ciphertext", "tag", "signature"}`

### Module 3: Digital Signatures for Integrity
- ElGamal signatures implemented from scratch
- Signs encrypted vault content (not plaintext)
- Verifies signature BEFORE decryption; aborts on tampering or wrong password

### Module 4: Secure Vault Export via Diffie-Hellman
- Diffie-Hellman implemented from scratch with separate parameters (`q`, `α`)
- Ephemeral DH keys generated per export session
- Two-way signed key exchange prevents MITM attacks
- Session key derived via `SHA-256(shared_secret_bytes).digest()` → AES-256-GCM
- Imported vault re-encrypted with recipient's master password and re-signed

### CTF Challenges (Part 2)
Solutions for 6 capture-the-flag tasks covering:
- Packet analysis (TCP stream reassembly + Base64 decoding)
- Image manipulation (PNG layer blending)
- Bit shifting (ASCII recovery)
- LSB steganography
- CBC padding oracle attack
- RSA key recovery (Fermat factorization)

---

## 🚀 Installation and Running

1. **Clone or download the project**
   ```bash
   git clone (https://github.com/TH4TM0F0/Secure_Password_Manager.git)
   cd secure-password-manager
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
3. **Run the CLI version**
   ```bash
   make cli
4. **Run the GUI version**
   ```bash
   make gui