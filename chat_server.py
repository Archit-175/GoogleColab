#!/usr/bin/env python3
"""
Simple Encrypted Chat Server
=============================
This server uses Diffie-Hellman key exchange to establish a shared secret,
then uses AES-GCM to encrypt all messages.

How it works:
1. Server starts and listens for a client connection
2. Server and client perform Diffie-Hellman key exchange
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

# Server configuration
HOST = '127.0.0.1'  # Localhost - only accessible from this machine
PORT = 5555         # Port to listen on

class EncryptedChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.client_socket = None
        self.aes_gcm = None
        
    def start(self):
        """Start the server and wait for a client connection."""
        # Create a TCP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for a client to connect...")
        
        # Accept a client connection
        self.client_socket, address = self.socket.accept()
        print(f"[+] Client connected from {address[0]}:{address[1]}")
        
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
            
            # Generate DH parameters (these define the mathematical group)
            # Using RFC 3526 2048-bit MODP group for security
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            
            # Serialize parameters to send to client
            params_bytes = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            
            # Send parameters to client
            self.client_socket.sendall(len(params_bytes).to_bytes(4, 'big'))
            self.client_socket.sendall(params_bytes)
            
            # Generate our private key and public key
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Serialize our public key
            server_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Exchange public keys: send ours, receive theirs
            self.client_socket.sendall(len(server_public_bytes).to_bytes(4, 'big'))
            self.client_socket.sendall(server_public_bytes)
            
            # Receive client's public key
            client_pub_size = int.from_bytes(self.client_socket.recv(4), 'big')
            client_public_bytes = self.client_socket.recv(client_pub_size)
            
            # Deserialize client's public key
            client_public_key = serialization.load_pem_public_key(client_public_bytes)
            
            # Perform key exchange: combine our private key with their public key
            # This produces a shared secret that both parties will compute to the same value
            shared_secret = private_key.exchange(client_public_key)
            
            # Derive a 256-bit AES key from the shared secret using HKDF
            # HKDF is a key derivation function that produces cryptographic keys
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
        """Read user input and send encrypted messages to the client."""
        try:
            while True:
                message = input()
                if message:
                    # Encrypt the message
                    encrypted = self.encrypt_message(message)
                    
                    # Send length prefix followed by encrypted message
                    self.client_socket.sendall(len(encrypted).to_bytes(4, 'big'))
                    self.client_socket.sendall(encrypted)
                    
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        except Exception as e:
            print(f"[-] Send error: {e}")
        finally:
            self.cleanup()
    
    def receive_messages(self):
        """Receive and decrypt messages from the client."""
        try:
            while True:
                # Receive message length
                length_bytes = self.client_socket.recv(4)
                if not length_bytes:
                    print("\n[*] Client disconnected")
                    break
                
                message_length = int.from_bytes(length_bytes, 'big')
                
                # Receive the encrypted message
                encrypted_data = b''
                while len(encrypted_data) < message_length:
                    chunk = self.client_socket.recv(message_length - len(encrypted_data))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                # Decrypt and display
                plaintext = self.decrypt_message(encrypted_data)
                print(f"Client: {plaintext}")
                
        except Exception as e:
            print(f"[-] Receive error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Close all sockets."""
        if self.client_socket:
            self.client_socket.close()
        if self.socket:
            self.socket.close()
        sys.exit(0)

def main():
    """Main entry point."""
    print("=" * 50)
    print("  Encrypted Chat Server (DH + AES-GCM)")
    print("=" * 50)
    
    server = EncryptedChatServer(HOST, PORT)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
