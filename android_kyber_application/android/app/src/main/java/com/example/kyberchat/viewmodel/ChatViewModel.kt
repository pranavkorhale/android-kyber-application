package com.example.kyberchat.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.kyberchat.crypto.CryptoManager
import com.example.kyberchat.network.ApiService
import com.example.kyberchat.network.Message
import com.example.kyberchat.network.RegisterRequest
import com.example.kyberchat.network.WebSocketClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

data class ChatState(
    val isRegistered: Boolean = false,
    val clientId: String = "",
    val messages: List<DecryptedMessage> = emptyList(),
    val error: String? = null,
    val debugLogs: List<String> = emptyList() // New debug log
)

data class DecryptedMessage(
    val senderId: String,
    val content: String,
    val isFromMe: Boolean
)

class ChatViewModel : ViewModel() {

    private val _state = MutableStateFlow(ChatState())
    val state = _state.asStateFlow()

    private val baseUrl = "http://10.0.2.2:8000" // Android Emulator localhost
    private val wsUrl = "ws://10.0.2.2:8000/ws"

    private val apiService: ApiService
    private val webSocketClient: WebSocketClient
    private var aesKey: SecretKeySpec? = null

    init {
        val okHttpClient = OkHttpClient.Builder().build()
        val retrofit = Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        apiService = retrofit.create(ApiService::class.java)
        webSocketClient = WebSocketClient(okHttpClient)

        // Listen for incoming messages
        viewModelScope.launch {
            launch {
                webSocketClient.messageFlow.collect { msg ->
                    handleIncomingMessage(msg)
                }
            }
            launch {
                webSocketClient.logFlow.collect { logMsg ->
                    log("WS: $logMsg")
                }
            }
        }
    }

    fun register(clientId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // 1. Generate Keys
                val kyberPk = CryptoManager.generateKyberKeys()
                val dilithiumPk = CryptoManager.generateDilithiumKeys()

                // 2. Register with Backend
                val response = apiService.register(RegisterRequest(clientId, kyberPk, dilithiumPk))
                
                if (response.isSuccessful && response.body() != null) {
                    // 3. Decapsulate & Derive AES Key
                    val ciphertext = response.body()!!.ciphertext
                    val sharedSecret = CryptoManager.decapsulate(ciphertext)
                    aesKey = CryptoManager.deriveAesKey(sharedSecret)

                    // 4. Connect WebSocket
                    webSocketClient.connect("$wsUrl/$clientId")

                    _state.value = _state.value.copy(isRegistered = true, clientId = clientId)
                } else {
                    _state.value = _state.value.copy(error = "Registration failed: ${response.code()}")
                }
            } catch (e: Exception) {
                e.printStackTrace()
                _state.value = _state.value.copy(error = "Error: ${e.message}")
            }
        }
    }

    fun testCrypto() {
        viewModelScope.launch(Dispatchers.Default) {
            try {
                log("--- Starting Crypto Self-Test ---")
                
                // 1. Generate Ephemeral Keys
                log("Generating Ephemeral Kyber Keys...")
                val generator = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator()
                generator.init(org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters(java.security.SecureRandom(), org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters.kyber512))
                val keyPair = generator.generateKeyPair()
                val pubKey = keyPair.public as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters
                val privKey = keyPair.private as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
                log("Keys Generated.")

                // 2. Encapsulate
                log("Encapsulating...")
                val kemGenerator = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator(java.security.SecureRandom())
                val encapsulation = kemGenerator.generateEncapsulated(pubKey)
                val sharedSecretEnc = encapsulation.secret
                val ciphertext = encapsulation.encapsulation
                log("Encapsulation Done. Ciphertext len: ${ciphertext.size}")

                // 3. Decapsulate
                log("Decapsulating...")
                val kemExtractor = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor(privKey)
                val sharedSecretDec = kemExtractor.extractSecret(ciphertext)
                log("Decapsulation Done.")

                // 4. Verify
                if (sharedSecretEnc.contentEquals(sharedSecretDec)) {
                    log("SUCCESS: Shared Secrets Match!")
                } else {
                    log("FAILURE: Shared Secrets Mismatch!")
                }
                log("--- Test Complete ---")

            } catch (e: Exception) {
                e.printStackTrace()
                log("Test Failed: ${e.message}")
            }
        }
    }

    private fun log(msg: String) {
        println("KyberChat: $msg")
        val newLogs = _state.value.debugLogs + msg
        _state.value = _state.value.copy(debugLogs = newLogs)
    }

    fun sendMessage(recipientId: String, content: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                log("Sending to $recipientId...")
                // 1. Fetch Recipient's Public Key
                val keyResponse = apiService.getKey(recipientId)
                if (!keyResponse.isSuccessful || keyResponse.body() == null) {
                    log("Error: Recipient $recipientId not found")
                    return@launch
                }
                val recipientKyberPk = keyResponse.body()!!.kyberPublicKey
                log("Got Recipient PK")

                // 2. Encapsulate
                val (ciphertext, sharedSecret) = CryptoManager.encapsulate(recipientKyberPk)
                val messageAesKey = CryptoManager.deriveAesKey(sharedSecret)
                log("Encapsulated Secret")

                // 3. Encrypt
                val (encryptedContent, nonce) = CryptoManager.encrypt(content, messageAesKey)

                // 4. Sign
                val clientIdBytes = _state.value.clientId.toByteArray(Charsets.UTF_8)
                val recipientIdBytes = recipientId.toByteArray(Charsets.UTF_8)
                val encryptedContentBytes = Base64.getDecoder().decode(encryptedContent)
                val nonceBytes = Base64.getDecoder().decode(nonce)
                val ciphertextBytes = Base64.getDecoder().decode(ciphertext)

                val payloadToSign = clientIdBytes + recipientIdBytes + encryptedContentBytes + nonceBytes + ciphertextBytes
                
                log("Signing Payload Bytes: ${payloadToSign.size} bytes")
                val payloadHash = java.security.MessageDigest.getInstance("SHA-256").digest(payloadToSign)
                log("Payload Hash (Base64): ${Base64.getEncoder().encodeToString(payloadHash)}")

                val signature = CryptoManager.sign(payloadHash)
                
                // Debug: Verify locally
                val isValid = CryptoManager.verify(payloadHash, signature)
                log("Local Sig Verify: $isValid")

                // 5. Send
                val message = Message(
                    senderId = _state.value.clientId,
                    recipientId = recipientId,
                    content = encryptedContent,
                    signature = signature,
                    nonce = nonce,
                    kemCiphertext = ciphertext
                )
                webSocketClient.sendMessage(message)
                log("Message Sent!")

                // Add to local chat
                val newMsg = DecryptedMessage(
                    senderId = _state.value.clientId,
                    content = content,
                    isFromMe = true
                )
                _state.value = _state.value.copy(messages = _state.value.messages + newMsg)

            } catch (e: Exception) {
                e.printStackTrace()
                log("Send Exception: ${e.message}")
            }
        }
    }

    private fun handleIncomingMessage(msg: Message) {
        try {
            log("Received msg from ${msg.senderId}")
            // 1. Decapsulate
            val sharedSecret = CryptoManager.decapsulate(msg.kemCiphertext)
            val messageAesKey = CryptoManager.deriveAesKey(sharedSecret)

            // 2. Decrypt
            val decryptedContent = CryptoManager.decrypt(msg.content, msg.nonce, messageAesKey)
            log("Decrypted successfully")
            
            val newMsg = DecryptedMessage(
                senderId = msg.senderId,
                content = decryptedContent,
                isFromMe = false
            )
            _state.value = _state.value.copy(messages = _state.value.messages + newMsg)
        } catch (e: Exception) {
            e.printStackTrace()
            log("Decryption Failed: ${e.message}")
            // Show encrypted content as fallback
            val newMsg = DecryptedMessage(
                senderId = msg.senderId,
                content = "Decryption Error: ${msg.content}",
                isFromMe = false
            )
            _state.value = _state.value.copy(messages = _state.value.messages + newMsg)
        }
    }
    
    override fun onCleared() {
        super.onCleared()
        webSocketClient.close()
    }
}
