# sender.py

import requests
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

def generate_key_pair():
    # Generate private key
    private_key = x25519.X25519PrivateKey.generate()
    
    # Get corresponding public key
    public_key = private_key.public_key()
    
    return private_key, public_key

def key_exchange(private_key, peer_public_key):
    # Perform key exchange
    shared_key = private_key.exchange(peer_public_key)
    
    # Derive symmetric key from shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key
        salt=None,
        info=b'ECDH Key Derivation',
        backend=default_backend()
    ).derive(shared_key)
    
    return derived_key

def encrypt_message(plaintext, key):
    # Generate a random nonce
    nonce = os.urandom(16)
    
    # Create a cipher object
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    
    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # Return nonce and ciphertext
    return nonce + ciphertext

# Specify the Flask server URL (replace 'flask_server_ip' with the public IP address of the machine hosting the Flask server)
flask_server_url = "http://192.168.1.4:5000"

# Read message from input.txt
with open("input.txt", "r") as file:
    message_to_send = file.read()

# Generate key pairs for devices A and B
private_key_A, public_key_A = generate_key_pair()
private_key_B, public_key_B = generate_key_pair()

# Perform key exchange between A and B
shared_key_A = key_exchange(private_key_A, public_key_B)
shared_key_B = key_exchange(private_key_B, public_key_A)

# Encrypt message with shared key
encrypted_message = encrypt_message(message_to_send, shared_key_A)

# Serialize private and public keys
private_key_A_bytes = private_key_A.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_B_bytes = public_key_B.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize the data to send
data_to_send = {
    'message': base64.b64encode(encrypted_message).decode(),
    'private_key': base64.b64encode(private_key_A_bytes).decode(),
    'peer_public_key': base64.b64encode(public_key_B_bytes).decode()
}

# Send the serialized data to the Flask server
response = requests.post(f"{flask_server_url}/deviceA/send_message", json=data_to_send)
