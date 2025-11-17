#!/usr/bin/env python3
"""
Simple Encrypted Chat Client
=============================
This client connects to the chat server and uses Diffie-Hellman key exchange
to establish a shared secret, then uses AES-GCM to encrypt all messages.

How it works:
1. Client connects to the server
2. Client and server perform Diffie-Hellman key exchange
3. Both derive the same AES encryption key from the shared secret
4. All subsequent messages are encrypted with AES-GCM
"""

import socket
import threading
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Server connection details
HOST = '127.0.0.1'  # Server address (localhost)
PORT = 5555         # Server port

class EncryptedChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.aes_gcm = None
        
    def connect(self):
        """Connect to the server."""
        print(f"[*] Connecting to server at {self.host}:{self.port}...")
        
        # Create a TCP socket and connect
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        
        print("[+] Connected to server!")
        
        # Perform key exchange
        if not self.key_exchange():
            print("[-] Key exchange failed!")
            return
        
        print("[+] Secure connection established!")
        print("[*] You can now send encrypted messages")
        print("[*] Type your message and press Enter to send")
        print("[*] Press Ctrl+C to exit\n")
        
        # Start threads for sending and receiving
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        self.send_messages()
    
    def key_exchange(self):
        """
        Perform Diffie-Hellman key exchange.
        
        Diffie-Hellman allows two parties to establish a shared secret over
        an insecure channel without ever transmitting the secret itself.
        """
        try:
            print("[*] Starting Diffie-Hellman key exchange...")
            
            # Receive DH parameters from server
            params_size = int.from_bytes(self.socket.recv(4), 'big')
            params_bytes = self.socket.recv(params_size)
            
            # Deserialize the parameters
            parameters = serialization.load_pem_parameters(params_bytes)
            
            # Generate our private key and public key using the same parameters
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Serialize our public key
            client_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Receive server's public key
            server_pub_size = int.from_bytes(self.socket.recv(4), 'big')
            server_public_bytes = self.socket.recv(server_pub_size)
            
            # Deserialize server's public key
            server_public_key = serialization.load_pem_public_key(server_public_bytes)
            
            # Send our public key to server
            self.socket.sendall(len(client_public_bytes).to_bytes(4, 'big'))
            self.socket.sendall(client_public_bytes)
            
            # Perform key exchange: combine our private key with server's public key
            # This produces the same shared secret that the server computed
            shared_secret = private_key.exchange(server_public_key)
            
            # Derive a 256-bit AES key from the shared secret using HKDF
            # We use the same parameters as the server to get the same key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=None,
                info=b'encrypted-chat'
            ).derive(shared_secret)
            
            # Initialize AES-GCM cipher with the derived key
            # GCM (Galois/Counter Mode) provides both encryption and authentication
            self.aes_gcm = AESGCM(derived_key)
            
            print("[+] Key exchange successful!")
            return True
            
        except Exception as e:
            print(f"[-] Key exchange error: {e}")
            return False
    
    def encrypt_message(self, plaintext):
        """Encrypt a message using AES-GCM."""
        # Generate a random 96-bit nonce (number used once)
        # The nonce ensures the same message encrypts differently each time
        nonce = os.urandom(12)
        
        # Encrypt the message
        # associated_data=None means no additional authenticated data
        ciphertext = self.aes_gcm.encrypt(nonce, plaintext.encode(), None)
        
        # Return nonce + ciphertext (receiver needs the nonce to decrypt)
        return nonce + ciphertext
    
    def decrypt_message(self, encrypted_data):
        """Decrypt a message using AES-GCM."""
        # Split nonce (first 12 bytes) and ciphertext (rest)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Decrypt and verify authenticity
        plaintext = self.aes_gcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    
    def send_messages(self):
        """Read user input and send encrypted messages to the server."""
        try:
            while True:
                message = input()
                if message:
                    # Encrypt the message
                    encrypted = self.encrypt_message(message)
                    
                    # Send length prefix followed by encrypted message
                    self.socket.sendall(len(encrypted).to_bytes(4, 'big'))
                    self.socket.sendall(encrypted)
                    
        except KeyboardInterrupt:
            print("\n[*] Disconnecting...")
        except Exception as e:
            print(f"[-] Send error: {e}")
        finally:
            self.cleanup()
    
    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        try:
            while True:
                # Receive message length
                length_bytes = self.socket.recv(4)
                if not length_bytes:
                    print("\n[*] Server disconnected")
                    break
                
                message_length = int.from_bytes(length_bytes, 'big')
                
                # Receive the encrypted message
                encrypted_data = b''
                while len(encrypted_data) < message_length:
                    chunk = self.socket.recv(message_length - len(encrypted_data))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                # Decrypt and display
                plaintext = self.decrypt_message(encrypted_data)
                print(f"Server: {plaintext}")
                
        except Exception as e:
            print(f"[-] Receive error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Close the socket."""
        if self.socket:
            self.socket.close()
        sys.exit(0)

def main():
    """Main entry point."""
    print("=" * 50)
    print("  Encrypted Chat Client (DH + AES-GCM)")
    print("=" * 50)
    
    client = EncryptedChatClient(HOST, PORT)
    try:
        client.connect()
    except KeyboardInterrupt:
        print("\n[*] Client stopped by user")
    except ConnectionRefusedError:
        print("[-] Connection refused. Make sure the server is running!")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
