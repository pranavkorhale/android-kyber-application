# End-to-End Encrypted Chat (Kyber + Dilithium)

This project implements a secure chat application using Post-Quantum Cryptography.

## Technologies
- **Key Exchange**: CRYSTALS-Kyber512 (Bouncy Castle / liboqs)
- **Signatures**: CRYSTALS-Dilithium2
- **Symmetric Encryption**: AES-256-GCM
- **Backend**: Python FastAPI
- **Frontend**: Android (Kotlin + Jetpack Compose)

## Project Structure
- `backend/`: FastAPI server
- `android/`: Android Studio project

## Setup Instructions

### Backend
1. Navigate to `backend/`:
   ```bash
   cd backend
   ```
2. Create virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Important**: You must install `liboqs` and its python wrapper for real security.
   - Follow instructions at: https://github.com/open-quantum-safe/liboqs-python
   - If `liboqs` is missing, the server will run in **MOCK MODE** (insecure, for testing only).
4. Run the server:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

### Android
1. Open `android/` in Android Studio.
2. Sync Gradle.
3. Ensure your Android Emulator can reach the backend.
   - The app uses `http://10.0.2.2:8000` which maps to `localhost:8000` on the host machine.
4. Run the app on two emulators (or one emulator and modify the code to act as two clients).
5. Register with different Client IDs (e.g., "Alice", "Bob").
6. Send messages between them.

## Security Note
The server performs the Kyber encapsulation to establish a secure channel with the client. Messages are encrypted with AES-GCM derived from this shared secret. The server *forwards* messages but technically possesses the key to decrypt them (since it performed the KEM). This design follows the specific requirements to "Store AES key" on the server while "Forwarding encrypted messages".
