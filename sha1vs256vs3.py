import hashlib
import time

# Mesaje cu complexitate crescută
messages = {
    "Mic": b"abc",
    "Mediu": b"The quick brown fox jumps over the lazy dog" * 10000,
    "Mare": b"A" * 10**10
      
}

algorithms = ['sha1', 'sha256', 'sha3_256']

print(f"{'Algoritm':<10} | {'Mesaj':<10} | {'Durata (ms)':<15} | {'Hash (primele 16 caractere)'}")
print("-" * 70)

for name, data in messages.items():
    for algo in algorithms:
        hasher = hashlib.new(algo)
        start = time.time()
        hasher.update(data)
        duration = (time.time() - start) * 1000  # convertim în milisecunde
        hash_preview = hasher.hexdigest()[:16]
        print(f"{algo:<10} | {name:<10} | {duration:<15.4f} | {hash_preview}")
