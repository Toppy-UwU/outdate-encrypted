#!/usr/bin/env python3
"""
Examples of RSA, ECC, and hash algorithms using pyca/cryptography.
These are shown for educational purposes; ensure proper usage in production.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

def demo_hash():
    """Demonstrate SHA-256 hash."""
    data = b'Message to hash'
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    print(f'Input: {data}')
    print(f'SHA-256: {hash_value.hex()}')
    return hash_value

def demo_rsa():
    """Demonstrate RSA encryption/decryption (OAEP) and signing."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Encryption
    message = b'Secret RSA message'
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'RSA encrypted: {ciphertext.hex()[:64]}...')
    
    # Decryption
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'RSA decrypted: {plaintext}')
    
    # Signing
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f'RSA signature: {signature.hex()[:64]}...')
    
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
        print('RSA signature valid')
    except Exception as e:
        print('RSA signature verification failed:', e)
    
    return private_key, public_key

def demo_ecc():
    """Demonstrate Elliptic Curve Diffie-Hellman (ECDH) and ECDSA signing."""
    # Generate ECC private key (SECP256R1)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # ECDH: derive shared secret
    # Generate another key pair for demonstration
    private_key2 = ec.generate_private_key(ec.SECP256R1())
    public_key2 = private_key2.public_key()
    
    shared_key1 = private_key.exchange(ec.ECDH(), public_key2)
    shared_key2 = private_key2.exchange(ec.ECDH(), public_key)
    # Use HKDF to derive a key
    derived_key1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key1)
    derived_key2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key2)
    print(f'ECDH shared key matches: {derived_key1 == derived_key2}')
    print(f'Derived key (hex): {derived_key1.hex()}')
    
    # ECDSA signing
    message = b'Message for ECDSA'
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print(f'ECDSA signature: {signature.hex()[:64]}...')
    
    # Verivation
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print('ECDSA signature valid')
    except Exception as e:
        print('ECDSA signature verification failed:', e)
    
    return private_key, public_key

if __name__ == '__main__':
    print('=== Hash, RSA, ECC Demo using pyca/cryptography ===')
    print()
    demo_hash()
    print()
    demo_rsa()
    print()
    demo_ecc()
