try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    print("WARNING: liboqs not found. Using MOCK crypto implementation.")

import base64
import hashlib
import os
from typing import Tuple

# Constants
KYBER_ALG = "Kyber768"
DILITHIUM_ALG = "ML-DSA-65"

def generate_kyber_encapsulation(client_public_key_b64: str) -> Tuple[str, bytes]:
    """
    Generates a Kyber encapsulation for the given client public key.
    Returns (ciphertext_b64, shared_secret_bytes).
    """
    if LIBOQS_AVAILABLE:
        client_public_key = base64.b64decode(client_public_key_b64)
        with oqs.KeyEncapsulation(KYBER_ALG) as kem:
            ciphertext, shared_secret = kem.encap_secret(client_public_key)
            return base64.b64encode(ciphertext).decode('utf-8'), shared_secret
    else:
        # Mock implementation
        # In real life, this is insecure. Only for testing when liboqs is missing.
        # Kyber512 Ciphertext length is 768 bytes.
        ciphertext = os.urandom(768) # Dummy ciphertext matching Kyber512 length
        shared_secret = hashlib.sha256(client_public_key_b64.encode()).digest() # Deterministic for testing
        return base64.b64encode(ciphertext).decode('utf-8'), shared_secret

def verify_dilithium_signature(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """
    Verifies a Dilithium signature.
    """
    if LIBOQS_AVAILABLE:
        public_key = base64.b64decode(public_key_b64)
        signature = base64.b64decode(signature_b64)
        with oqs.Signature(DILITHIUM_ALG) as sig:
            print(f"DEBUG: Verify {DILITHIUM_ALG}")
            print(f"DEBUG: PK Len: {len(public_key)} (Expected {sig.length_public_key})")
            print(f"DEBUG: Sig Len: {len(signature)} (Expected {sig.length_signature})")
            print(f"DEBUG: Msg value (first 32 bytes hex): {message[:32].hex()}")
            return sig.verify(message, signature, public_key)
    else:
        # Mock implementation: Always return True for testing flow
        return True

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives a 32-byte AES key from the Kyber shared secret using SHA-256.
    """
    return hashlib.sha256(shared_secret).digest()
