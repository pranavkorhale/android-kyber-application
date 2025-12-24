from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict, Optional
import hashlib
import json
import base64
import os

from models import RegisterRequest, RegisterResponse, Message
from crypto_utils import generate_kyber_encapsulation, verify_dilithium_signature, derive_aes_key

app = FastAPI()

CLIENTS_FILE = "clients.json"

class ConnectionManager:
    def __init__(self):
        # active_connections: client_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        # clients: client_id -> {aes_key, dilithium_pk, kyber_pk}
        self.clients: Dict[str, dict] = self.load_clients()

    def load_clients(self):
        if os.path.exists(CLIENTS_FILE):
            try:
                with open(CLIENTS_FILE, "r") as f:
                    data = json.load(f)
                    # Convert hex aes_key back to bytes if needed, 
                    # but for simplicity let's store aes_key as hex in JSON and bytes in memory if we were using it.
                    # Actually, we only use aes_key for the initial response? 
                    # No, we use it for something? 
                    # Wait, the server derives AES key but doesn't seem to use it for E2E anymore?
                    # Ah, the server uses it for the *registration response* (encrypted). 
                    # But for messaging, we use E2E.
                    # However, we might need it if we wanted to send server messages.
                    # Let's just load it.
                    return data
            except Exception as e:
                print(f"Error loading clients: {e}")
        return {}

    def save_clients(self):
        try:
            with open(CLIENTS_FILE, "w") as f:
                json.dump(self.clients, f, indent=4)
        except Exception as e:
            print(f"Error saving clients: {e}")

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"Client {client_id} connected.")
        
        # Send Test/Welcome Message to verify connectivity
        # Using dummy values for fields to pass Pydantic/Gson validation
        # welcome_msg = {
        #     "sender_id": "System",
        #     "recipient_id": client_id,
        #     "content": "VkVySUZZX0NPTk5FQ1RJT04=", # "VERIFY_CONNECTION" in Base64
        #     "signature": "ZHVtbXk=", # "dummy"
        #     "nonce": "ZHVtbXk=", # "dummy"
        #     "kem_ciphertext": "ZHVtbXk=" # "dummy"
        # }
        # await websocket.send_json(welcome_msg)
        # print(f"Sent Welcome message to {client_id}")

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            print(f"Client {client_id} disconnected.")

    async def send_personal_message(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            ws = self.active_connections[client_id]
            try:
                print(f"Sending to {client_id} via WebSocket...")
                await ws.send_json(message)
                print(f"Sent to {client_id}.")
            except Exception as e:
                print(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)
        else:
            print(f"Error: {client_id} is not connected.")

    def register_client(self, client_id: str, aes_key: bytes, dilithium_pk: str, kyber_pk: str):
        # Store keys persistently
        self.clients[client_id] = {
            "aes_key_hex": aes_key.hex(), # Store as hex for JSON serialization
            "dilithium_pk": dilithium_pk,
            "kyber_pk": kyber_pk
        }
        self.save_clients()

    def get_client_key(self, client_id: str) -> Optional[dict]:
        if client_id in self.clients:
            return {
                "dilithium_pk": self.clients[client_id]["dilithium_pk"],
                "kyber_pk": self.clients[client_id]["kyber_pk"]
            }
        return None

manager = ConnectionManager()

@app.post("/register", response_model=RegisterResponse)
async def register(request: RegisterRequest):
    # 1. Generate Kyber Encapsulation
    try:
        ciphertext_b64, shared_secret = generate_kyber_encapsulation(request.kyber_public_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Kyber encapsulation failed: {str(e)}")

    # 2. Derive AES Key
    aes_key = derive_aes_key(shared_secret)

    # 3. Store Client Info
    manager.register_client(request.client_id, aes_key, request.dilithium_public_key, request.kyber_public_key)

    return RegisterResponse(ciphertext=ciphertext_b64)

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            print(f"DEBUG: Received raw data: {data}")
            message_dict = json.loads(data)
            
            # Validate Message Structure
            try:
                msg = Message(**message_dict)
            except Exception as e:
                print(f"ERROR: Malformed message: {e}")
                continue # Ignore malformed

            # Verify Signature
            sender_keys = manager.get_client_key(msg.sender_id)
            if not sender_keys:
                print(f"Sender {msg.sender_id} not found")
                continue
            
            sender_pk = sender_keys["dilithium_pk"]
            
            # Construct payload to verify (Canonical Byte Format)
            try:
                sender_id_bytes = msg.sender_id.encode('utf-8')
                recipient_id_bytes = msg.recipient_id.encode('utf-8')
                content_bytes = base64.b64decode(msg.content)
                nonce_bytes = base64.b64decode(msg.nonce)
                kem_ciphertext_bytes = base64.b64decode(msg.kem_ciphertext)
                
                payload = sender_id_bytes + recipient_id_bytes + content_bytes + nonce_bytes + kem_ciphertext_bytes
                
                # Hash payload (SHA-256)
                payload_hash = hashlib.sha256(payload).digest()
            except Exception as e:
                print(f"Error constructing payload for verification: {e}")
                continue

            print(f"--- Verification ---")
            is_valid_hash = verify_dilithium_signature(sender_pk, payload_hash, msg.signature)
            is_valid_raw = verify_dilithium_signature(sender_pk, payload, msg.signature)
            
            if is_valid_hash:
                 print(f"Signature Verification (Hash): SUCCESS")
            elif is_valid_raw:
                 print(f"Signature Verification (Raw): SUCCESS (Warning: Client using legacy raw signing)")
            else:
                 print(f"Signature Verification: FAILED")
                 print(f"Start Hex: {payload[:32].hex()}")
                 # Decide whether to block:
                 # User said "I want to use dilithium kyber for signature", implying they want it verified.
                 # So we should block if invalid.
                 # print("Dropping invalid message.")
                 # continue
                 # However, since we are debugging, I will WARN but ALLOW for now so they can verify the flow?
                 # No, "I want to use" usually means "Enforce it".
                 # But if it fails, the app breaks.
                 # I will Block ID it fails.
                 print("ERROR: Dropping message due to invalid signature.")
                 continue

            print(f"Forwarding message from {msg.sender_id} to {msg.recipient_id}")
            # Forward to Recipient
            print(f"DEBUG: Outgoing JSON: {json.dumps(message_dict)}")
            await manager.send_personal_message(message_dict, msg.recipient_id)

    except WebSocketDisconnect:
        manager.disconnect(client_id)
@app.get("/key/{client_id}")
async def get_key(client_id: str):
    keys = manager.get_client_key(client_id)
    if keys:
        return keys
    raise HTTPException(status_code=404, detail="Client not found")
