import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# -------------------- PART A: AES-256-GCM --------------------

def derive_aes_key(master_secret: bytes, info: bytes = b"ics-aes-key") -> bytes:
    """
    Derive a 256-bit AES key using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,   # 256-bit key
        salt=None,
        info=info,
    )
    return hkdf.derive(master_secret)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns (nonce, ciphertext_with_tag)
    """
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad if aad else None)


# -------------------- PART B: ECDSA (P-256) --------------------

def generate_ecdsa_keypair():
    """Generate ECDSA P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_command(private_key, command: bytes) -> bytes:
    """Sign command using ECDSA-SHA256."""
    signature = private_key.sign(command, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(public_key, command: bytes, signature: bytes) -> bool:
    """Verify ECDSA signature."""
    try:
        public_key.verify(signature, command, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# -------------------- DEMO --------------------

if __name__ == "__main__":
    print("=" * 60)
    print(" Cryptographic Engine -- AES-GCM + ECDSA Demo")
    print("=" * 60)

    # 1. Derive AES-256 key
    master_secret = os.urandom(32)
    aes_key = derive_aes_key(master_secret)
    print(f"\n[+] Derived AES-256 Key: {aes_key.hex()[:32]}... (truncated)")

    # 2. Sample SCADA command
    command = b"SET_VALVE=OPEN;GRID_SECTOR=7;PRIORITY=HIGH"
    aad = b"ICS-NODE-007"
    print(f"\n[+] Original Command: {command.decode()}")

    # 3. Encrypt
    nonce, ciphertext = encrypt_aes_gcm(aes_key, command, aad)
    print(f"[+] Nonce (hex): {nonce.hex()}")
    print(f"[+] Ciphertext (hex): {ciphertext.hex()[:48]}... (truncated)")

    # 4. Decrypt
    decrypted = decrypt_aes_gcm(aes_key, nonce, ciphertext, aad)
    print(f"\n[+] Decrypted Command: {decrypted.decode()}")
    print(f"[+] Integrity Check: {'PASSED' if decrypted == command else 'FAILED'}")

    # 5. ECDSA Sign
    private_key, public_key = generate_ecdsa_keypair()
    signature = sign_command(private_key, command)
    print(f"\n[+] ECDSA Signature: {signature.hex()[:48]}... (truncated)")

    # 6. Verify signature
    is_valid = verify_signature(public_key, command, signature)
    print(f"[+] Signature Valid: {is_valid}")

    # 7. Tamper test
    tampered_command = b"SET_VALVE=CLOSE;GRID_SECTOR=7;PRIORITY=HIGH"
    is_valid_tampered = verify_signature(public_key, tampered_command, signature)
    print(f"[+] Tampered Signature Valid: {is_valid_tampered}")
    is_valid_tampered = verify_signature(public_key, tampered_command, signature)

    print(f"\n[+] Tampered Command  : {tampered_command.decode()}")
    print(f"[+] Signature Valid (tampered) : {is_valid_tampered}  <-- TAMPER DETECTED")
    print("\n[+] Cryptographic Engine demo complete.")