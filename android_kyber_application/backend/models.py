from pydantic import BaseModel

class RegisterRequest(BaseModel):
    client_id: str
    kyber_public_key: str  # Base64 encoded
    dilithium_public_key: str  # Base64 encoded

class RegisterResponse(BaseModel):
    ciphertext: str  # Base64 encoded Kyber encapsulation

class Message(BaseModel):
    sender_id: str
    recipient_id: str
    content: str  # Base64 encoded encrypted content
    signature: str  # Base64 encoded Dilithium signature
    nonce: str # Base64 encoded AES nonce
    kem_ciphertext: str # Base64 encoded Kyber ciphertext for the recipient
