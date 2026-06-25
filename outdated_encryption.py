#!/usr/bin/env python3
"""
Example of outdated encryption algorithms using pyca/cryptography library.
DO NOT USE IN PRODUCTION.
"""
import hashlib
from cryptography.hazmat.primitives.ciphers.algorithms import DES, TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import UnsupportedAlgorithm
import os

def demo_md5():
    """MD5 is cryptographically broken and unsuitable for further use."""
    data = b'Secret message'
    md5_hash = hashlib.md5(data).hexdigest()
    print(f'MD5 of {data}: {md5_hash}')
    return md5_hash

def demo_des():
    """DES is outdated due to its small key size (56-bit)."""
    key = os.urandom(8)  # DES key size 64 bits (8 bytes)
    iv = os.urandom(8)   # DES block size 64 bits
    cipher = Cipher(DES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(DES.block_size).padder()
    data = b'Secret12'  # will be padded
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    print(f'DES key: {key.hex()}')
    print(f'IV: {iv.hex()}')
    print(f'Encrypted: {encrypted.hex()}')
    # Decrypt to verify
    decryptor = Cipher(DES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    unpadder = padding.PKCS7(DES.block_size).unpadder()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    try:
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    except Exception as e:
        decrypted = b''
    print(f'Decrypted: {decrypted}')
    return encrypted

def demo_3des():
    """Triple DES is considered obsolete and vulnerable to meet-in-the-middle attacks."""
    key = os.urandom(24)  # TripleDES key size 168 bits (24 bytes)
    iv = os.urandom(8)    # block size 64 bits
    cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(TripleDES.block_size).padder()
    data = b'Secret1234'  # will be padded
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    print(f'3DES key: {key.hex()}')
    print(f'IV: {iv.hex()}')
    print(f'Encrypted: {encrypted.hex()}')
    # Decrypt to verify
    decryptor = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    unpadder = padding.PKCS7(TripleDES.block_size).unpadder()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    try:
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    except Exception as e:
        decrypted = b''
    print(f'Decrypted: {decrypted}')
    return encrypted

if __name__ == '__main__':
    print('=== Outdated Encryption Demo using pyca/cryptography ===')
    demo_md5()
    print()
    demo_des()
    print()
    demo_3des()
