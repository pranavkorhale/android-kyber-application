package com.example.kyberchat

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.kyberchat.viewmodel.ChatViewModel
import com.example.kyberchat.viewmodel.DecryptedMessage
import androidx.compose.runtime.collectAsState

class MainActivity : ComponentActivity() {
    private val viewModel: ChatViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    ChatApp(viewModel)
                }
            }
        }
    }
}

@Composable
fun ChatApp(viewModel: ChatViewModel) {
    val state by viewModel.state.collectAsState()

    if (!state.isRegistered) {
        RegistrationScreen(
            onRegister = { clientId -> viewModel.register(clientId) },
            error = state.error
        )
    } else {
        ChatScreen(
            clientId = state.clientId,
            messages = state.messages,
            debugLogs = state.debugLogs,
            onSend = { recipient, msg -> viewModel.sendMessage(recipient, msg) },
            onTestCrypto = { viewModel.testCrypto() }
        )
    }
}

@Composable
fun RegistrationScreen(onRegister: (String) -> Unit, error: String?) {
    var clientId by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Kyber Chat Registration", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(32.dp))
        
        OutlinedTextField(
            value = clientId,
            onValueChange = { clientId = it },
            label = { Text("Enter Client ID") }
        )
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(onClick = { onRegister(clientId) }) {
            Text("Register & Connect")
        }
        
        if (error != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(error, color = Color.Red)
        }
    }
}

@Composable
fun ChatScreen(
    clientId: String, 
    messages: List<DecryptedMessage>, 
    debugLogs: List<String>,
    onSend: (String, String) -> Unit,
    onTestCrypto: () -> Unit
) {
    var recipientId by remember { mutableStateOf("") }
    var messageText by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Logged in as: $clientId", style = MaterialTheme.typography.titleMedium)
        
        // Debug Logs
        LazyColumn(modifier = Modifier.height(100.dp).fillMaxWidth().background(Color.LightGray)) {
            items(debugLogs.takeLast(5)) { log ->
                Text(log, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(2.dp))
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        OutlinedTextField(
            value = recipientId,
            onValueChange = { recipientId = it },
            label = { Text("Recipient ID") },
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Button(onClick = {
                if (recipientId.isNotEmpty() && messageText.isNotEmpty()) {
                    onSend(recipientId, messageText)
                    messageText = ""
                }
            }) {
                Text("Send")
            }
            Button(onClick = { onTestCrypto() }) {
                Text("Test Crypto")
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            reverseLayout = true
        ) {
            items(messages.reversed()) { msg ->
                MessageBubble(msg)
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = messageText,
                onValueChange = { messageText = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Type a message...") }
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(onClick = {
                if (recipientId.isNotEmpty() && messageText.isNotEmpty()) {
                    onSend(recipientId, messageText)
                    messageText = ""
                }
            }) {
                Text("Send")
            }
        }
    }
}

@Composable
fun MessageBubble(message: DecryptedMessage) {
    val align = if (message.isFromMe) Alignment.End else Alignment.Start
    val color = if (message.isFromMe) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer
    
    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = align) {
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = color,
            modifier = Modifier.padding(4.dp)
        ) {
            Column(modifier = Modifier.padding(8.dp)) {
                if (!message.isFromMe) {
                    Text(message.senderId, style = MaterialTheme.typography.labelSmall)
                }
                Text(message.content)
            }
        }
    }
}
