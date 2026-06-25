#!/usr/bin/env python3
"""
Demo of correct and incorrect usage of RSA, ECC, and Hash using hashlib and pyca/cryptography.
Correct: strong parameters, modern algorithms.
Incorrect: weak parameters, outdated algorithms.
Hash: using hashlib (since cryptography does not provide MD5).
"""
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidKey
import os

# ------------------------------
# Hash section (using hashlib)
def hash_correct():
    """Correct: SHA-256"""
    data = b'Message to hash'
    hash_val = hashlib.sha256(data).digest()
    print(f'[Hash Correct] SHA-256: {hash_val.hex()}')
    return hash_val

def hash_incorrect():
    """Incorrect: MD5 (cryptographically broken)"""
    data = b'Message to hash'
    hash_val = hashlib.md5(data).digest()
    print(f'[Hash Incorrect] MD5: {hash_val.hex()}')
    return hash_val

# RSA section
def rsa_correct():
    """Correct: RSA 2048-bit with OAEP-PSS"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    message = b'Secret RSA message'
    # Encryption
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decryption
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Signing
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Verify
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
        sig_ok = True
    except Exception:
        sig_ok = False
    print(f'[RSA Correct] Key size: {private_key.key_size} bits')
    print(f'[RSA Correct] Encryption/decryption OK: {plaintext == message}')
    print(f'[RSA Correct] Signature valid: {sig_ok}')
    return private_key, public_key

def rsa_incorrect():
    """Incorrect: RSA 512-bit (too small) with PKCS1v15 (considered less secure)"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=512)  # weak
    public_key = private_key.public_key()
    message = b'Secret RSA message'
    try:
        ciphertext = public_key.encrypt(
            message,
            padding.PKCS1v15()  # outdated padding
        )
        plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
        enc_ok = (plaintext == message)
    except Exception as e:
        print(f'[RSA Incorrect] Encryption error: {e}')
        enc_ok = False
    # Signing with PKCS1v15 (less preferred)
    try:
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        sig_ok = True
    except Exception as e:
        print(f'[RSA Incorrect] Signature error: {e}')
        sig_ok = False
    print(f'[RSA Incorrect] Key size: {private_key.key_size} bits')
    print(f'[RSA Incorrect] Encryption/decryption OK: {enc_ok}')
    print(f'[RSA Incorrect] Signature valid: {sig_ok}')
    return private_key, public_key

# ECC section
def ecc_correct():
    """Correct: SECP256R1 for ECDH and ECDSA"""
    # ECDH
    priv1 = ec.generate_private_key(ec.SECP256R1())
    pub1 = priv1.public_key()
    priv2 = ec.generate_private_key(ec.SECP256R1())
    pub2 = priv2.public_key()
    shared1 = priv1.exchange(ec.ECDH(), pub2)
    shared2 = priv2.exchange(ec.ECDH(), pub1)
    # Derive key
    derived1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared1)
    derived2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared2)
    ecdh_ok = derived1 == derived2
    # ECDSA
    message = b'Message for ECDSA'
    priv_sign = ec.generate_private_key(ec.SECP256R1())
    pub_sign = priv_sign.public_key()
    signature = priv_sign.sign(message, ec.ECDSA(hashes.SHA256()))
    try:
        pub_sign.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        sig_ok = True
    except Exception:
        sig_ok = False
    print(f'[ECC Correct] ECDH shared key matches: {ecdh_ok}')
    print(f'[ECC Correct] ECDSA signature valid: {sig_ok}')
    return priv1, pub1, priv_sign, pub_sign

def ecc_incorrect():
    """Incorrect: SECP192R1 (smaller curve) and using ECDH without KDF (raw shared secret)"""
    # Weak curve
    priv1 = ec.generate_private_key(ec.SECP192R1())
    pub1 = priv1.public_key()
    priv2 = ec.generate_private_key(ec.SECP192R1())
    pub2 = priv2.public_key()
    shared1 = priv1.exchange(ec.ECDH(), pub2)
    shared2 = priv2.exchange(ec.ECDH(), pub1)
    # No KDF, just compare raw (should match but weak)
    ecdh_ok = shared1 == shared2
    # ECDSA with same weak curve
    message = b'Message for ECDSA'
    priv_sign = ec.generate_private_key(ec.SECP192R1())
    pub_sign = priv_sign.public_key()
    signature = priv_sign.sign(message, ec.ECDSA(hashes.SHA256()))
    try:
        pub_sign.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        sig_ok = True
    except Exception:
        sig_ok = False
    print(f'[ECC Incorrect] Curve: SECP192R1 (192-bit)')
    print(f'[ECC Incorrect] ECDH shared key matches (raw): {ecdh_ok}')
    print(f'[ECC Incorrect] ECDSA signature valid: {sig_ok}')
    return priv1, pub1, priv_sign, pub_sign

if __name__ == '__main__':
    print('=== Correct vs Incorrect Usage Demo ===')
    print()
    hash_correct()
    hash_incorrect()
    print()
    rsa_correct()
    rsa_incorrect()
    print()
    ecc_correct()
    ecc_incorrect()
