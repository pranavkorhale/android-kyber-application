package com.example.kyberchat.network

import com.google.gson.annotations.SerializedName

data class RegisterRequest(
    @SerializedName("client_id") val clientId: String,
    @SerializedName("kyber_public_key") val kyberPublicKey: String,
    @SerializedName("dilithium_public_key") val dilithiumPublicKey: String
)

data class RegisterResponse(
    @SerializedName("ciphertext") val ciphertext: String
)

data class Message(
    @SerializedName("sender_id") val senderId: String,
    @SerializedName("recipient_id") val recipientId: String,
    @SerializedName("content") val content: String, // Encrypted
    @SerializedName("signature") val signature: String,
    @SerializedName("nonce") val nonce: String,
    @SerializedName("kem_ciphertext") val kemCiphertext: String // For E2E
)

data class KeyResponse(
    @SerializedName("kyber_pk") val kyberPublicKey: String,
    @SerializedName("dilithium_pk") val dilithiumPublicKey: String
)
