from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import time
import os

# Generare fișier de test
with open("testfile_2gb.bin", "wb") as f:
    f.write(os.urandom(2 * 1024 * 1024 * 1024))  # 2GB

# Citire fișier
with open("testfile_2gb.bin", "rb") as f:
    file_data = f.read()

# AES setup (ECB)
key = get_random_bytes(16)  # AES-128
cipher = AES.new(key, AES.MODE_ECB)

# Padding pentru alinierea la 16 bytes
padded_data = pad(file_data, 16)

# Măsurare timp criptare
start = time.perf_counter()
cipher.encrypt(padded_data)
end = time.perf_counter()

# Timp în milisecunde
elapsed = (end - start) * 1000
print(f"Timp criptare AES (10MB): {elapsed:.2f} ms")
