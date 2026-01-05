import os
import time
import psutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Generăm un mesaj mare (~1MB)
message = os.urandom(1024 * 1024)


def measure_encryption(algorithm, key, nonce_or_iv):
    process = psutil.Process(os.getpid())
    start_mem = process.memory_info().rss
    start = time.time()

    if algorithm == "AES":
        cipher = Cipher(
            algorithms.AES(key), modes.CFB(nonce_or_iv), backend=default_backend()
        )
    elif algorithm == "ChaCha20":
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce_or_iv), mode=None, backend=default_backend()
        )
    elif algorithm == "Blowfish":
        cipher = Cipher(
            algorithms.Blowfish(key), modes.CFB(nonce_or_iv), backend=default_backend()
        )
    else:
        return None

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    duration = time.time() - start
    end_mem = process.memory_info().rss
    mem_used = end_mem - start_mem
    return duration, mem_used


# Test AES
aes_key = os.urandom(32)
aes_iv = os.urandom(16)
aes_time, aes_mem = measure_encryption("AES", aes_key, aes_iv)

# Test ChaCha20
chacha_key = os.urandom(32)
chacha_nonce = os.urandom(16)
chacha_time, chacha_mem = measure_encryption("ChaCha20", chacha_key, chacha_nonce)

# Test Blowfish
blowfish_key = os.urandom(16)
blowfish_iv = os.urandom(8)
blowfish_time, blowfish_mem = measure_encryption("Blowfish", blowfish_key, blowfish_iv)


# Rezultate
print("\n📊 Criptare (timp și memorie)")
print(f"AES      - Timp: {aes_time:.6f}s | RAM: {aes_mem / 1024:.2f} KB")
print(f"ChaCha20 - Timp: {chacha_time:.6f}s | RAM: {chacha_mem / 1024:.2f} KB")
print(f"Blowfish - Timp: {blowfish_time:.6f}s | RAM: {blowfish_mem / 1024:.2f} KB")
