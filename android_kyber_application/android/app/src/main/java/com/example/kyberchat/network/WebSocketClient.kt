package com.example.kyberchat.network

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import com.google.gson.Gson
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow

class WebSocketClient(private val client: OkHttpClient) {

    private var webSocket: WebSocket? = null
    private val gson = Gson()
    
    private val _messageChannel = Channel<Message>()
    val messageFlow = _messageChannel.receiveAsFlow()

    private val _logChannel = Channel<String>()
    val logFlow = _logChannel.receiveAsFlow()

    private fun log(msg: String) {
        _logChannel.trySend(msg)
        println("WebSocketClient: $msg")
    }

    fun connect(url: String) {
        val request = Request.Builder().url(url).build()
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                super.onOpen(webSocket, response)
                log("WebSocket Connected")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                super.onMessage(webSocket, text)
                log("Received raw: ${text.take(50)}...")
                try {
                    val message = gson.fromJson(text, Message::class.java)
                    _messageChannel.trySend(message)
                } catch (e: Exception) {
                    e.printStackTrace()
                    log("JSON Parse Error: ${e.message}")
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                super.onClosing(webSocket, code, reason)
                log("WebSocket Closing: $reason")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                super.onFailure(webSocket, t, response)
                t.printStackTrace()
                log("WebSocket Failure: ${t.message}")
            }
        })
    }

    fun sendMessage(message: Message) {
        val json = gson.toJson(message)
        webSocket?.send(json)
    }

    fun close() {
        webSocket?.close(1000, "Goodbye")
    }
}
