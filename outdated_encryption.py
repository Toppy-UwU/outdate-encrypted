#!/usr/bin/env python3
"""
Examples of correct and incorrect RSA usage using pyca/cryptography.
For educational purposes only.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

def rsa_correct():
    """Correct: RSA 2048-bit with OAEP encryption and PSS signing"""
    print('=== Correct RSA ===')
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Encryption with OAEP
    message = b'Secret message for RSA'
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'Ciphertext length: {len(ciphertext)} bytes')
    
    # Decryption
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'Decryption matches: {plaintext == message}')
    
    # Signing with PSS
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f'Signature length: {len(signature)} bytes')
    
    # Verification
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print('Signature verification: SUCCESS')
    except InvalidSignature:
        print('Signature verification: FAILED')
    
    return private_key, public_key

def rsa_incorrect():
    """Incorrect: RSA 1024-bit (too small) with PKCS1v15 padding (considered weak)"""
    print('\n=== Incorrect RSA ===')
    # Generate weak key (1024-bit is considered insufficient today)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # weak key size
    )
    public_key = private_key.public_key()
    
    message = b'Secret message for RSA'
    
    # Encryption with PKCS1v15 (known to have vulnerabilities if used incorrectly)
    try:
        ciphertext = public_key.encrypt(
            message,
            padding.PKCS1v15()
        )
        print(f'Ciphertext length: {len(ciphertext)} bytes')
        # Decryption
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        print(f'Decryption matches: {plaintext == message}')
    except Exception as e:
        print(f'Encryption/decryption error: {e}')
        plaintext = b''
    
    # Signing with PKCS1v15 (less preferred than PSS)
    try:
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f'Signature length: {len(signature)} bytes')
        # Verification
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print('Signature verification: SUCCESS')
    except Exception as e:
        print(f'Signature error: {e}')
    
    return private_key, public_key

if __name__ == '__main__':
    rsa_correct()
    rsa_incorrect()
