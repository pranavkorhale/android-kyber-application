import asyncio
import websockets
import requests
import json
import base64
import os

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws"

CLIENT_ID_A = "client_a"
CLIENT_ID_B = "client_b"

# Mock Keys (since we are using mock crypto on server too)
KYBER_PK_A = base64.b64encode(b"kyber_pk_a").decode()
DILITHIUM_PK_A = base64.b64encode(b"dilithium_pk_a").decode()

KYBER_PK_B = base64.b64encode(b"kyber_pk_b").decode()
DILITHIUM_PK_B = base64.b64encode(b"dilithium_pk_b").decode()

def register(client_id, kyber_pk, dilithium_pk):
    print(f"Registering {client_id}...")
    resp = requests.post(f"{BASE_URL}/register", json={
        "client_id": client_id,
        "kyber_public_key": kyber_pk,
        "dilithium_public_key": dilithium_pk
    })
    if resp.status_code == 200:
        print(f"Success: {resp.json()}")
        return resp.json()["ciphertext"]
    else:
        print(f"Failed: {resp.text}")
        return None

async def test_messaging():
    # 1. Register
    register(CLIENT_ID_A, KYBER_PK_A, DILITHIUM_PK_A)
    register(CLIENT_ID_B, KYBER_PK_B, DILITHIUM_PK_B)

    # 2. Connect WS
    async with websockets.connect(f"{WS_URL}/{CLIENT_ID_A}") as ws_a, \
               websockets.connect(f"{WS_URL}/{CLIENT_ID_B}") as ws_b:
        
        print("Connected both clients.")

        # 3. Send Message A -> B
        # Mock encrypted content
        msg_content = base64.b64encode(b"encrypted_hello").decode()
        nonce = base64.b64encode(b"mock_nonce").decode()
        mock_kem_ciphertext_b64 = base64.b64encode(b"mock_kem_ciphertext").decode()
        
        # We need to construct the payload and hash it to "sign" it (mock signature)
        try:
            sender_id_bytes = CLIENT_ID_A.encode('utf-8')
            recipient_id_bytes = CLIENT_ID_B.encode('utf-8')
            content_bytes = base64.b64decode(msg_content)
            nonce_bytes = base64.b64decode(nonce)
            kem_ciphertext_bytes = base64.b64decode(mock_kem_ciphertext_b64)
            
            payload = sender_id_bytes + recipient_id_bytes + content_bytes + nonce_bytes + kem_ciphertext_bytes
            import hashlib
            payload_hash = hashlib.sha256(payload).digest()
            # print(f"DEBUG: Payload hash (hex): {payload_hash.hex()}")
        except Exception as e:
            print(f"Error preparing mock signature: {e}")
        
        # Mock Signature: In this mock setup, the signature is just "mock_signature_b64"
        # The SERVER will verify this signature against the payload_hash using MOCK verification (which returns True)
        # OR if liboqs is present, it will try to verify. 
        # Since we don't have real keys here easily without liboqs locally, we rely on the server side mock check 
        # or the fact that previously it passed because of mock.
        # KEY POINT: The structure of what triggers verification logic must be correct.
        
        signature = base64.b64encode(b"mock_signature").decode()

        msg = {
            "sender_id": CLIENT_ID_A,
            "recipient_id": CLIENT_ID_B,
            "content": msg_content,
            "signature": signature,
            "nonce": nonce,
            "kem_ciphertext": mock_kem_ciphertext_b64
        }

        await ws_a.send(json.dumps(msg))
        print(f"Sent message from A to B: {msg}")

        # 4. Receive on B
        received = await ws_b.recv()
        print(f"B received: {received}")
        
        received_dict = json.loads(received)
        assert received_dict["content"] == msg_content
        print("Verification Successful!")

if __name__ == "__main__":
    asyncio.run(test_messaging())
