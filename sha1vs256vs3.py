import hashlib
import time

with open("fisier_mediu.bin", "wb") as f:
    for _ in range(200):
        f.write(b"A" * 1024 * 1024)  # 200MB

with open("fisier_mare.bin", "wb") as f:
    for _ in range(1000):
        f.write(b"B" * 1024 * 1024)  # 1GB

# Citire fisiere
with open("fisier_mediu.bin", "rb") as f:
    mediu_data = f.read()

with open("fisier_mare.bin", "rb") as f:
    mare_data = f.read()

# Mesaje cu dimensiuni realiste
messages = {
    "Mic": b"A" * 10**7,
    "Mediu": mediu_data,
    "Mare": mare_data,
}

algorithms = ["sha1", "sha256", "sha3_256"]

print(f"{'Algoritm':<10} | {'Mesaj':<10} | {'Durata (ms)':<15} | {'Hash (16 chars)'}")
print("-" * 70)

for name, data in messages.items():
    for algo in algorithms:
        start = time.time()

        hasher = hashlib.new(algo)
        hasher.update(data)

        duration = (time.time() - start) * 1000
        hash_preview = hasher.hexdigest()[:16]

        print(
            f"{algo:<10} | {name:<10} | {duration:<15.4f} | {hash_preview}", flush=True
        )
