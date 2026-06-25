#!/usr/bin/env python3
"""
Example of outdated encryption algorithms for educational purposes.
DO NOT USE IN PRODUCTION.
"""
import hashlib
from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def demo_md5():
    data = b'Secret message'
    md5_hash = hashlib.md5(data).hexdigest()
    print(f'MD5 of {data}: {md5_hash}')
    return md5_hash

def demo_des():
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    data = b'Secret12'
    padded = pad(data, DES.block_size)
    encrypted = cipher.encrypt(padded)
    print(f'DES key: {key.hex()}')
    print(f'Encrypted: {encrypted.hex()}')
    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
    print(f'Decrypted: {decrypted}')
    return encrypted

def demo_3des():
    key = get_random_bytes(24)
    cipher = DES3.new(key, DES3.MODE_ECB)
    data = b'Secret1234'
    padded = pad(data, DES3.block_size)
    encrypted = cipher.encrypt(padded)
    print(f'3DES key: {key.hex()}')
    print(f'Encrypted: {encrypted.hex()}')
    decrypted = unpad(cipher.decrypt(encrypted), DES3.block_size)
    print(f'Decrypted: {decrypted}')
    return encrypted

if __name__ == '__main__':
    print('=== Outdated Encryption Demo ===')
    demo_md5()
    print()
    demo_des()
    print()
    demo_3des()
