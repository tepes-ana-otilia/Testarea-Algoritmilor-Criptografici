from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import time
import os

# Citire fișier existent (10MB)
with open("testfile_10mb.bin", "rb") as f:
    file_data = f.read()

# DES setup (ECB)
key = get_random_bytes(8)
cipher = DES.new(key, DES.MODE_ECB)

# Padding pentru alinierea la 8 bytes
padded_data = pad(file_data, 8)

# Măsurare timp criptare
start = time.perf_counter()
cipher.encrypt(padded_data)
end = time.perf_counter()

# Timp în milisecunde
elapsed = (end - start) * 1000
print(f"Timp criptare DES (10MB): {elapsed:.2f} ms")
