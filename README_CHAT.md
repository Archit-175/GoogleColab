# Encrypted Chat Application

A simple, educational implementation of an encrypted chat system using Diffie-Hellman key exchange and AES-GCM encryption. This project consists of two Python programs that allow secure communication over TCP.

## 🔐 Features

- **Diffie-Hellman Key Exchange**: Securely establish a shared secret without transmitting it
- **AES-GCM Encryption**: Military-grade encryption for all messages
- **Minimal & Readable**: Small codebase with extensive comments for learning
- **Terminal-based**: Easy to run in separate terminal windows

## 📚 How It Works

### Diffie-Hellman Key Exchange
Diffie-Hellman is a cryptographic protocol that allows two parties to establish a shared secret over an insecure channel. Here's how it works:

1. Both parties agree on public parameters (a large prime number and a generator)
2. Each party generates a private key (kept secret)
3. Each party derives a public key from their private key
4. They exchange public keys
5. Each party combines their private key with the other's public key
6. Both parties end up with the same shared secret (without ever transmitting it!)

### AES-GCM Encryption
AES (Advanced Encryption Standard) with GCM (Galois/Counter Mode) provides:
- **Encryption**: Scrambles the message so only the holder of the key can read it
- **Authentication**: Ensures the message hasn't been tampered with
- **Nonce-based**: Each message is encrypted differently even if the content is the same

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This will install the `cryptography` library, which provides the cryptographic primitives we need.

### Alternative Installation (if requirements.txt doesn't work)

```bash
pip install cryptography
```

## 💻 Usage

### Step 1: Start the Server

Open a terminal and run:

```bash
python3 chat_server.py
```

You should see:
```
==================================================
  Encrypted Chat Server (DH + AES-GCM)
==================================================
[*] Server listening on 127.0.0.1:5555
[*] Waiting for a client to connect...
```

### Step 2: Start the Client

Open a **second terminal** and run:

```bash
python3 chat_client.py
```

You should see:
```
==================================================
  Encrypted Chat Client (DH + AES-GCM)
==================================================
[*] Connecting to server at 127.0.0.1:5555...
[+] Connected to server!
[*] Starting Diffie-Hellman key exchange...
[+] Key exchange successful!
[+] Secure connection established!
[*] You can now send encrypted messages
```

### Step 3: Chat!

Now you can type messages in either terminal:
- Messages sent from the **server terminal** will appear as "Server: [message]" on the client
- Messages sent from the **client terminal** will appear as "Client: [message]" on the server

All messages are **automatically encrypted** before transmission!

### Step 4: Exit

Press `Ctrl+C` in either terminal to exit.

## 📖 Example Session

**Terminal 1 (Server):**
```
[*] Server listening on 127.0.0.1:5555
[*] Waiting for a client to connect...
[+] Client connected from 127.0.0.1:54321
[*] Starting Diffie-Hellman key exchange...
[+] Key exchange successful!
[+] Secure connection established!
[*] You can now send encrypted messages

Hello from server!
Client: Hi from client!
This is encrypted!
Client: Yes, totally secure!
```

**Terminal 2 (Client):**
```
[*] Connecting to server at 127.0.0.1:5555...
[+] Connected to server!
[*] Starting Diffie-Hellman key exchange...
[+] Key exchange successful!
[+] Secure connection established!
[*] You can now send encrypted messages

Server: Hello from server!
Hi from client!
Server: This is encrypted!
Yes, totally secure!
```

## 🔍 Technical Details

### Cryptographic Parameters
- **DH Key Size**: 2048 bits (RFC 3526 MODP Group)
- **AES Key Size**: 256 bits (AES-256)
- **GCM Nonce Size**: 96 bits (12 bytes)
- **Key Derivation**: HKDF with SHA-256

### Security Considerations
This is an **educational implementation** designed for learning. For production use, you should:
- Add certificate-based authentication to prevent man-in-the-middle attacks
- Implement proper error handling and logging
- Use TLS/SSL for the transport layer
- Add replay attack protection
- Implement perfect forward secrecy with ephemeral keys
- Add rate limiting and DoS protection

### Network Configuration
- **Host**: 127.0.0.1 (localhost - only accessible from your machine)
- **Port**: 5555 (you can change this in both files if needed)

To make the server accessible from other machines on your network, change `HOST = '127.0.0.1'` to `HOST = '0.0.0.0'` in `chat_server.py` and update the client to use your server's IP address.

## 🐛 Troubleshooting

### "Connection refused" error
- Make sure the server is running before starting the client
- Check that both programs are using the same port number
- Verify that no firewall is blocking the connection

### "ModuleNotFoundError: No module named 'cryptography'"
- Run `pip install -r requirements.txt` or `pip install cryptography`
- If using Python 3, try `pip3` instead of `pip`

### Messages not appearing
- Ensure you press Enter after typing your message
- Check that both programs completed the key exchange successfully

## 📝 Code Structure

### chat_server.py
- `EncryptedChatServer` class: Main server logic
  - `start()`: Initialize server and accept connections
  - `key_exchange()`: Perform Diffie-Hellman key exchange
  - `encrypt_message()` / `decrypt_message()`: Handle encryption/decryption
  - `send_messages()` / `receive_messages()`: Handle message I/O

### chat_client.py
- `EncryptedChatClient` class: Main client logic
  - `connect()`: Connect to server
  - `key_exchange()`: Perform Diffie-Hellman key exchange
  - `encrypt_message()` / `decrypt_message()`: Handle encryption/decryption
  - `send_messages()` / `receive_messages()`: Handle message I/O

## 📚 Learning Resources

To learn more about the cryptography used in this project:
- [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [GCM Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [Python Cryptography Library](https://cryptography.io/)

## 📄 License

This is an educational project. Feel free to use and modify for learning purposes.
