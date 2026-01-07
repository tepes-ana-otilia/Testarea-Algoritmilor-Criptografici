import hashlib

# Citește fișierele binar
with open("shattered-1.pdf", "rb") as f1, open("shattered-2.pdf", "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()

# Calculează hash-urile
hash1 = hashlib.sha1(data1).hexdigest()
hash2 = hashlib.sha1(data2).hexdigest()

# Afișează rezultatul
print("SHA-1 Hash shattered-1.pdf:", hash1)
print("SHA-1 Hash shattered-2.pdf:", hash2)

# Demonstrație coliziune
if hash1 == hash2:
    print("Coliziune demonstrată: ambele fișiere au același hash SHA-1.")
else:
    print("Fără coliziune.")
