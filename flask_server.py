from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

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
    # Pad the plaintext to ensure it's a multiple of block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV and ciphertext
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    # Split IV and ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return plaintext.decode()

@app.route('/deviceA/send_message', methods=['POST'])
def send_message_from_A_to_B():
    data = request.json
    message = data['message']
    
    # Generate key pairs for devices A and B
    private_key_A, public_key_A = generate_key_pair()
    private_key_B, public_key_B = generate_key_pair()

    # Perform key exchange between A and B
    shared_key_A = key_exchange(private_key_A, public_key_B)
    shared_key_B = key_exchange(private_key_B, public_key_A)

    # Encrypt message with shared key
    encrypted_message = encrypt_message(message, shared_key_A)

    # Decrypt message with shared key
    decrypted_message = decrypt_message(encrypted_message, shared_key_B)

    return jsonify({'response': f'Message received by B: {decrypted_message}'})

@app.route('/deviceB/send_message', methods=['POST'])
def send_message_from_B_to_A():
    data = request.json
    message = data['message']
    
    # Generate key pairs for devices A and B
    private_key_A, public_key_A = generate_key_pair()
    private_key_B, public_key_B = generate_key_pair()

    # Perform key exchange between A and B
    shared_key_A = key_exchange(private_key_A, public_key_B)
    shared_key_B = key_exchange(private_key_B, public_key_A)

    # Encrypt message with shared key
    encrypted_message = encrypt_message(message, shared_key_B)

    # Decrypt message with shared key
    decrypted_message = decrypt_message(encrypted_message, shared_key_A)

    return jsonify({'response': f'Message received by A: {decrypted_message}'})

if __name__ == '__main__':
    app.run(debug=True)
