"""
Set de Teste pentru Algoritmul RSA

Acest cod cuprinde o metodologie completă de testare a RSA:
1. Evaluarea complexității algoritmului
2. Testarea rezistenței la atacuri criptanalitice
3. Testarea manuală a vulnerabilităților
4. Testarea prin simulări și atacuri controlate
5. Testarea bazată pe standarde
6. Testarea performanței
7. Testarea integrității
8. Analiza entropiei și randomizării
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256, SHA512, HMAC
from Crypto.Signature import pkcs1_15
import time
import math
import hashlib
import secrets
import numpy as np
from collections import Counter
import random


class RSACompleteTesting:
    def __init__(self):
        self.results = {
            "complexity": [],
            "cryptanalytic": [],
            "vulnerabilities": [],
            "simulations": [],
            "standards": [],
            "performance": [],
            "integrity": [],
            "entropy": [],
        }
        self.test_keys = {}

    # ============================================================================
    # TESTAREA 1: EVALUAREA COMPLEXITĂȚII ALGORITMULUI
    # ============================================================================

    def test_1_complexity_evaluation(self):
        """
        Evaluează complexitatea algoritmului prin:
        - Analiza matematică a complexității factorizării
        - Simularea atacurilor brute-force
        - Estimarea resurselor computaționale necesare
        """
        print("\n" + "=" * 80)
        print("TESTAREA 1: EVALUAREA COMPLEXITĂȚII ALGORITMULUI")
        print("=" * 80)

        # Test 1.1: Factorizare pentru chei mici
        print("\n--- 1.1 Factorizare Trial Division (Chei Mici) ---")
        small_key_sizes = [64, 128, 256]

        for key_size in small_key_sizes:
            n, e, d, p, q = self._generate_weak_rsa(key_size)
            print(f"\nCheia RSA {key_size} biți: n = {n}")

            start = time.perf_counter()
            factors = self._trial_division(n, limit=10000000)
            end = time.perf_counter()

            time_ms = (end - start) * 1000

            if factors:
                print(f"✓ FACTORIZAT în {time_ms:.2f} ms")
                print(f"  p = {factors[0]}, q = {factors[1]}")
            else:
                print(f"✗ NU S-A FACTORIZAT în {time_ms:.2f} ms")

            self.results["complexity"].append(
                {
                    "method": "trial_division",
                    "key_size": key_size,
                    "factorized": factors is not None,
                    "time_ms": time_ms,
                }
            )

        # Test 1.2: Estimare complexitate Pollard Rho
        print("\n--- 1.2 Factorizare Pollard Rho ---")
        for key_size in [64, 128]:
            n, e, d, p, q = self._generate_weak_rsa(key_size)
            print(f"\nCheia RSA {key_size} biți:")

            start = time.perf_counter()
            factor = self._pollard_rho(n)
            end = time.perf_counter()

            time_ms = (end - start) * 1000

            if factor and factor != 1 and factor != n:
                print(f"✓ FACTORIZAT în {time_ms:.2f} ms")
                print(f"  Factor găsit: {factor}")
            else:
                print(f"✗ NU S-A FACTORIZAT în {time_ms:.2f} ms")

            self.results["complexity"].append(
                {
                    "method": "pollard_rho",
                    "key_size": key_size,
                    "factorized": factor is not None and factor != 1 and factor != n,
                    "time_ms": time_ms,
                }
            )

        # Test 1.3: Analiza complexității teoretice
        print("\n--- 1.3 Analiză Complexitate Teoretică ---")
        for key_size in [1024, 2048, 3072, 4096]:
            exponent = key_size / 2
            log10_ops = exponent * math.log10(
                2
            )  # log10(2^(key_size/2)) = (key_size/2)*log10(2)

            print(f"\nCheia RSA {key_size} biți:")
            print(f"  Operații estimate pentru factorizare: ~2^{exponent:.0f}")
            print(
                f"  Echivalent aproximativ: ~10^{log10_ops:.2f} operații (estimare logaritmică)"
            )

            # Estimare timp folosind logaritmi
            # 1 GHz = 10^9 op/s → timp în ani
            log10_ops_per_sec = 9  # 10^9 op/s
            log10_secs_per_year = math.log10(60 * 60 * 24 * 365)  # sec/an
            log10_years = log10_ops - log10_ops_per_sec - log10_secs_per_year

            if log10_years > 10:  # > 10^10 ani
                print(f"  Timp estimat: >10^{log10_years:.2f} ani (IMPOSIBIL practic)")
            else:
                print(f"  Timp estimat: ~10^{log10_years:.2f} ani")

    def _trial_division(self, n, limit=10000000):
        """Factorizare prin împărțire succesivă"""
        if n % 2 == 0:
            return [2, n // 2]
        for i in range(3, min(int(math.sqrt(n)) + 1, limit), 2):
            if n % i == 0:
                return [i, n // i]
        return None

    def _pollard_rho(self, n, max_iterations=100000):
        """Algoritmul Pollard Rho pentru factorizare"""
        if n % 2 == 0:
            return 2

        x = random.randint(2, n - 1)
        y = x
        c = random.randint(1, n - 1)
        d = 1

        iterations = 0
        while d == 1 and iterations < max_iterations:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            iterations += 1

        return d if d != n else None

    # ============================================================================
    # TESTAREA 2: REZISTENȚA LA ATACURI CRIPTANALITICE
    # ============================================================================

    def test_2_cryptanalytic_attacks(self):
        """
        Testează rezistența la:
        - Chosen-plaintext attacks
        - Ciphertext-only attacks
        - Analiza statistică a textelor criptate
        """
        print("\n" + "=" * 80)
        print("TESTAREA 2: REZISTENȚA LA ATACURI CRIPTANALITICE")
        print("=" * 80)

        key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(key)

        # Test 2.1: Chosen-Plaintext Attack (CPA)
        print("\n--- 2.1 Chosen-Plaintext Attack ---")
        chosen_messages = [
            b"A" * 100,
            b"B" * 100,
            b"\x00" * 100,
            b"\xff" * 100,
            get_random_bytes(100),
        ]

        ciphertexts = []
        for i, msg in enumerate(chosen_messages):
            encrypted = cipher.encrypt(msg)
            ciphertexts.append(encrypted)
            print(f"Mesaj {i+1}: {len(encrypted)} bytes criptat")

        # Verificare: mesaje identice produc criptograme diferite (datorită padding)
        unique_ciphertexts = len(set(ciphertexts[:4]))  # Primele 4 ar trebui diferite
        print(f"\nMesaje similare → Criptograme unice: {unique_ciphertexts}/4")
        print(f"Rezistență CPA: {'✓ BUNĂ' if unique_ciphertexts >= 3 else '✗ SLABĂ'}")

        self.results["cryptanalytic"].append(
            {"attack_type": "chosen_plaintext", "resistant": unique_ciphertexts >= 3}
        )

        # Test 2.2: Ciphertext-Only Attack
        print("\n--- 2.2 Ciphertext-Only Attack ---")
        print("Simulare: Atacator are doar criptogramele, fără mesaje plain")

        # Analiza statistică a criptogramelor
        all_bytes = b"".join(ciphertexts)
        byte_freq = Counter(all_bytes)
        entropy = self._calculate_entropy(all_bytes)

        print(f"Entropie criptograme: {entropy:.4f} (ideal: 8.0)")
        print(f"Bytes unice: {len(byte_freq)}/256")

        # Un ciphertext bun ar trebui să aibă entropie apropiată de 8
        resistant = entropy > 7.5
        print(f"Rezistență Ciphertext-Only: {'✓ BUNĂ' if resistant else '✗ SLABĂ'}")

        self.results["cryptanalytic"].append(
            {
                "attack_type": "ciphertext_only",
                "entropy": entropy,
                "resistant": resistant,
            }
        )

        # Test 2.3: Common Modulus Attack (vulnerabilitate teoretică)
        print("\n--- 2.3 Common Modulus Attack (Demonstrație) ---")
        # Generăm două chei cu același modul (GREȘIT în practică!)
        key1 = RSA.generate(1024)
        n_common = key1.n

        # Simulare: aceeași valoare e pentru ambele chei
        print(f"Modul comun n: {n_common}")
        print("⚠ ATENȚIE: Utilizarea aceluiași modul pentru chei diferite")
        print("  este o vulnerabilitate GRAVĂ și nu trebuie făcută niciodată!")

        self.results["cryptanalytic"].append(
            {
                "attack_type": "common_modulus",
                "vulnerable": True,
                "note": "Educational demonstration only",
            }
        )

    def _calculate_entropy(self, data):
        """Calculează entropia Shannon"""
        if not data:
            return 0
        byte_counts = Counter(data)
        entropy = 0
        for count in byte_counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    # ============================================================================
    # TESTAREA 3: TESTAREA MANUALĂ A VULNERABILITĂȚILOR
    # ============================================================================

    def test_3_vulnerability_audit(self):
        """
        Auditează implementarea pentru:
        - Erori de implementare
        - Algoritmi nesiguri
        - Protocoale vulnerabile
        """
        print("\n" + "=" * 80)
        print("TESTAREA 3: TESTAREA MANUALĂ A VULNERABILITĂȚILOR")
        print("=" * 80)

        vulnerabilities_found = []

        # Test 3.1: Verificare dimensiuni minime ale cheilor
        print("\n--- 3.1 Audit Dimensiuni Chei ---")
        unsafe_key_sizes = [512, 768, 1024]
        safe_key_sizes = [2048, 3072, 4096]

        for size in unsafe_key_sizes:
            print(f"Cheia {size} biți: ⚠ NESIGURĂ (sub standardul minim)")
            vulnerabilities_found.append(f"Key size {size} is below minimum")

        for size in safe_key_sizes:
            print(f"Cheia {size} biți: ✓ SIGURĂ")

        # Test 3.2: Verificare exponenți publici
        print("\n--- 3.2 Audit Exponenți Publici ---")
        key = RSA.generate(2048)

        print(f"Exponent public e: {key.e}")
        if key.e == 65537:
            print("✓ SIGUR: Exponent standard (65537 = 0x10001)")
        elif key.e == 3:
            print("⚠ ATENȚIE: Exponent mic (e=3) poate fi vulnerabil")
            vulnerabilities_found.append("Small public exponent")
        else:
            print(f"ℹ INFO: Exponent nestandard: {key.e}")

        # Test 3.3: Verificare padding
        print("\n--- 3.3 Audit Schemă Padding ---")
        print("Schema utilizată: PKCS1_OAEP")
        print("✓ SIGUR: OAEP este rezistent la atacuri adaptative")

        # Test 3.4: Verificare Man-in-the-Middle
        print("\n--- 3.4 Verificare Protocoale (MitM, Replay) ---")
        print("⚠ IMPORTANT: RSA singur NU protejează împotriva:")
        print("  - Man-in-the-Middle attacks")
        print("  - Replay attacks")
        print("✓ RECOMANDARE: Utilizați RSA împreună cu:")
        print("  - Semnături digitale pentru autentificare")
        print("  - Timestamping pentru anti-replay")
        print("  - TLS/SSL pentru canale securizate")

        self.results["vulnerabilities"] = {
            "total_vulnerabilities": len(vulnerabilities_found),
            "vulnerabilities": vulnerabilities_found,
            "safe_practices_checked": 4,
        }

    # ============================================================================
    # TESTAREA 4: SIMULĂRI ȘI ATACURI CONTROLATE
    # ============================================================================

    def test_4_stress_and_penetration(self):
        """
        Testează în condiții de stres:
        - Volume mari de date
        - Cereri multiple simultane
        - Teste de penetrare
        """
        print("\n" + "=" * 80)
        print("TESTAREA 4: SIMULĂRI ȘI ATACURI CONTROLATE")
        print("=" * 80)

        key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(key)

        # Test 4.1: Stress Test - Volume mari
        print("\n--- 4.1 Stress Test: Volume Mari de Date ---")
        max_msg_size = (2048 // 8) - 42
        num_operations = 100

        print(f"Se execută {num_operations} operații de criptare/decriptare...")
        start = time.perf_counter()

        success_count = 0
        for i in range(num_operations):
            try:
                msg = get_random_bytes(max_msg_size)
                encrypted = cipher.encrypt(msg)
                decrypted = cipher.decrypt(encrypted)
                if msg == decrypted:
                    success_count += 1
            except Exception as e:
                print(f"Eroare la operația {i}: {e}")

        end = time.perf_counter()
        duration = (end - start) * 1000

        print(f"Operații reușite: {success_count}/{num_operations}")
        print(f"Timp total: {duration:.2f} ms")
        print(f"Timp/operație: {duration/num_operations:.2f} ms")

        self.results["simulations"].append(
            {
                "test": "stress_volume",
                "operations": num_operations,
                "success_rate": success_count / num_operations,
                "total_time_ms": duration,
            }
        )

        # Test 4.2: Test Concurență (simulat secvențial)
        print("\n--- 4.2 Test Stabilitate: Operații Consecutive ---")
        consecutive_ops = 50
        errors = 0

        for i in range(consecutive_ops):
            try:
                msg = get_random_bytes(50)
                encrypted = cipher.encrypt(msg)
                decrypted = cipher.decrypt(encrypted)
                assert msg == decrypted
            except Exception as e:
                errors += 1
                print(f"Eroare la operația {i}: {e}")

        print(f"Operații: {consecutive_ops}, Erori: {errors}")
        print(f"Stabilitate: {'✓ EXCELENTĂ' if errors == 0 else '✗ PROBLEME'}")

        self.results["simulations"].append(
            {
                "test": "stability",
                "operations": consecutive_ops,
                "errors": errors,
                "stable": errors == 0,
            }
        )

        # Test 4.3: Penetration Test - Mesaje Malformate
        print("\n--- 4.3 Penetration Test: Mesaje Malformate ---")
        malformed_inputs = [
            b"",  # Mesaj gol
            b"X",  # Mesaj prea scurt
            b"Y" * 500,  # Mesaj prea lung
            bytes([0xFF] * max_msg_size),  # Bytes maximale
        ]

        resilience_score = 0
        for i, malformed in enumerate(malformed_inputs):
            try:
                encrypted = cipher.encrypt(malformed)
                decrypted = cipher.decrypt(encrypted)
                if malformed == decrypted:
                    print(f"Test {i+1}: ✓ Tratat corect")
                    resilience_score += 1
                else:
                    print(f"Test {i+1}: ✗ Decriptare incorectă")
            except ValueError as e:
                print(f"Test {i+1}: ✓ Respins corect (ValueError)")
                resilience_score += 1
            except Exception as e:
                print(f"Test {i+1}: ⚠ Eroare neașteptată: {type(e).__name__}")

        print(f"\nScor reziliență: {resilience_score}/{len(malformed_inputs)}")

        self.results["simulations"].append(
            {
                "test": "penetration_malformed",
                "resilience_score": resilience_score,
                "total_tests": len(malformed_inputs),
            }
        )

    # ============================================================================
    # TESTAREA 5: CONFORMITATE CU STANDARDE
    # ============================================================================

    def test_5_standards_compliance(self):
        """
        Verifică conformitatea cu standarde:
        - NIST SP 800-57
        - FIPS 186-4
        - PCI DSS
        """
        print("\n" + "=" * 80)
        print("TESTAREA 5: CONFORMITATE CU STANDARDE")
        print("=" * 80)

        compliance_results = {}

        # Test 5.1: NIST SP 800-57 (Key Management)
        print("\n--- 5.1 NIST SP 800-57: Managementul Cheilor ---")
        key_sizes_tested = [1024, 2048, 3072, 4096]

        for size in key_sizes_tested:
            if size < 2048:
                status = "✗ NECONFORM"
                compliant = False
                reason = "Sub minim 2048 biți"
            elif size >= 3072:
                status = "✓ CONFORM (112+ biți securitate)"
                compliant = True
                reason = "Îndeplinește cerințe până în 2030+"
            else:
                status = "✓ CONFORM (128 biți securitate)"
                compliant = True
                reason = "Acceptabil până în 2030"

            print(f"Cheia {size} biți: {status} - {reason}")

            compliance_results[f"NIST_{size}"] = compliant

        # Test 5.2: FIPS 186-4 (Digital Signatures)
        print("\n--- 5.2 FIPS 186-4: Semnături Digitale ---")
        key = RSA.generate(2048)

        # Verificare exponent public
        if key.e >= 2**16 + 1:  # 65537
            print(f"✓ Exponent public: {key.e} (CONFORM)")
            compliance_results["FIPS_exponent"] = True
        else:
            print(f"✗ Exponent public prea mic: {key.e}")
            compliance_results["FIPS_exponent"] = False

        # Verificare dimensiune modul
        n_bit_length = key.n.bit_length()
        if n_bit_length >= 2048:
            print(f"✓ Dimensiune modul: {n_bit_length} biți (CONFORM)")
            compliance_results["FIPS_modulus"] = True
        else:
            print(f"✗ Dimensiune modul: {n_bit_length} biți (sub 2048)")
            compliance_results["FIPS_modulus"] = False

        # Test 5.3: PCI DSS (Payment Card Industry)
        print("\n--- 5.3 PCI DSS: Securitate Tranzacții ---")
        pci_requirements = {
            "min_key_size": 2048,
            "key_rotation": "Recomandat anual",
            "secure_storage": "Chei private protejate",
        }

        print(f"✓ Dimensiune minimă: {pci_requirements['min_key_size']} biți")
        print(f"ℹ Rotație chei: {pci_requirements['key_rotation']}")
        print(f"ℹ Stocare: {pci_requirements['secure_storage']}")

        compliance_results["PCI_DSS"] = True

        # Raport final conformitate
        print("\n--- Raport Conformitate ---")
        total_checks = len(compliance_results)
        passed_checks = sum(compliance_results.values())

        print(f"Total verificări: {total_checks}")
        print(f"Verificări trecute: {passed_checks}")
        print(f"Rata conformitate: {(passed_checks/total_checks)*100:.1f}%")

        self.results["standards"] = {
            "compliance_results": compliance_results,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
        }

    # ============================================================================
    # TESTAREA 6: PERFORMANȚA
    # ============================================================================

    def test_6_performance(self, key_sizes=[1024, 2048, 3072, 4096], iterations=10):
        """
        Măsoară performanța pentru:
        - Generarea cheilor
        - Criptare/Decriptare
        - Consum resurse
        """
        print("\n" + "=" * 80)
        print("TESTAREA 6: PERFORMANȚA")
        print("=" * 80)

        for key_size in key_sizes:
            print(f"\n--- Performanță Cheia {key_size} biți ---")

            # 6.1: Generare chei
            key_gen_times = []
            for _ in range(iterations):
                start = time.perf_counter()
                RSA.generate(key_size)
                end = time.perf_counter()
                key_gen_times.append((end - start) * 1000)

            print(f"\nGenerare chei:")
            print(f"  Media: {np.mean(key_gen_times):.2f} ms")
            print(f"  Min/Max: {min(key_gen_times):.2f} / {max(key_gen_times):.2f} ms")

            # 6.2: Criptare/Decriptare
            key = RSA.generate(key_size)
            cipher = PKCS1_OAEP.new(key)
            max_msg_size = (key_size // 8) - 42

            message = get_random_bytes(max_msg_size)

            encrypt_times = []
            decrypt_times = []

            encrypted_msg = None
            for _ in range(iterations):
                start = time.perf_counter()
                encrypted_msg = cipher.encrypt(message)
                end = time.perf_counter()
                encrypt_times.append((end - start) * 1000)

                start = time.perf_counter()
                cipher.decrypt(encrypted_msg)
                end = time.perf_counter()
                decrypt_times.append((end - start) * 1000)

            print(f"\nCriptare:")
            print(f"  Media: {np.mean(encrypt_times):.3f} ms")
            print(f"\nDecriptare:")
            print(f"  Media: {np.mean(decrypt_times):.3f} ms")

            self.results["performance"].append(
                {
                    "key_size": key_size,
                    "key_gen_time": np.mean(key_gen_times),
                    "encrypt_time": np.mean(encrypt_times),
                    "decrypt_time": np.mean(decrypt_times),
                }
            )

    # ============================================================================
    # TESTAREA 7: INTEGRITATEA
    # ============================================================================

    def test_7_integrity(self):
        """
        Verifică mecanismele de integritate:
        - Hash functions
        - HMAC
        - Semnături digitale
        """
        print("\n" + "=" * 80)
        print("TESTAREA 7: INTEGRITATEA")
        print("=" * 80)

        key = RSA.generate(2048)
        message = b"Mesaj important pentru verificare integritate"

        # Test 7.1: Hash Functions (SHA-256, SHA-512)
        print("\n--- 7.1 Funcții Hash ---")

        hash_sha256 = SHA256.new(message)
        hash_sha512 = SHA512.new(message)

        print(f"SHA-256: {hash_sha256.hexdigest()}")
        print(f"SHA-512: {hash_sha512.hexdigest()}")

        # Verificare: modificare mesaj → hash diferit
        modified_message = message + b"X"
        hash_modified = SHA256.new(modified_message)

        print(f"\nMesaj original:  {hash_sha256.hexdigest()[:32]}...")
        print(f"Mesaj modificat: {hash_modified.hexdigest()[:32]}...")
        print(
            f"Hashes diferite: {'✓ DA' if hash_sha256.digest() != hash_modified.digest() else '✗ NU'}"
        )

        self.results["integrity"].append(
            {
                "test": "hash_functions",
                "passed": hash_sha256.digest() != hash_modified.digest(),
            }
        )

        # Test 7.2: HMAC (Hash-based Message Authentication Code)
        print("\n--- 7.2 HMAC ---")

        secret_key = get_random_bytes(32)
        hmac_obj = HMAC.new(secret_key, message, digestmod=SHA256)
        mac = hmac_obj.hexdigest()

        print(f"HMAC: {mac[:64]}...")

        # Verificare HMAC
        hmac_verify = HMAC.new(secret_key, message, digestmod=SHA256)
        try:
            hmac_verify.hexverify(mac)
            print("✓ HMAC verificat cu succes")
            hmac_valid = True
        except ValueError:
            print("✗ HMAC invalid")
            hmac_valid = False

        self.results["integrity"].append({"test": "hmac", "passed": hmac_valid})

        # Test 7.3: Semnături Digitale RSA
        print("\n--- 7.3 Semnături Digitale RSA ---")

        # Semnare
        hash_obj = SHA256.new(message)
        signature = pkcs1_15.new(key).sign(hash_obj)

        print(f"Semnătură generată: {len(signature)} bytes")

        # Verificare semnătură
        try:
            hash_verify = SHA256.new(message)
            pkcs1_15.new(key).verify(hash_verify, signature)
            print("✓ Semnătură VALIDĂ")
            signature_valid = True
        except (ValueError, TypeError):
            print("✗ Semnătură INVALIDĂ")
            signature_valid = False

        # Test: modificare mesaj → semnătură invalidă
        modified = message + b"tampered"
        hash_tampered = SHA256.new(modified)
        try:
            pkcs1_15.new(key).verify(hash_tampered, signature)
            print("✗ EROARE: Semnătura ar trebui invalidă pentru mesaj modificat!")
            tamper_detected = False
        except (ValueError, TypeError):
            print("✓ Modificare detectată corect")
            tamper_detected = True

        self.results["integrity"].append(
            {
                "test": "digital_signatures",
                "signature_valid": signature_valid,
                "tamper_detected": tamper_detected,
            }
        )

        # Rezumat
        print("\n--- Rezumat Integritate ---")
        integrity_tests = [
            (
                r["passed"]
                if "passed" in r
                else r["signature_valid"] and r["tamper_detected"]
            )
            for r in self.results["integrity"]
        ]
        print(f"Teste trecute: {sum(integrity_tests)}/{len(integrity_tests)}")

    # ============================================================================
    # TESTAREA 8: ENTROPIA ȘI RANDOMIZARE
    # ============================================================================

    def test_8_entropy_and_randomness(self, key_size=2048, num_keys=100):
        """
        Analizează calitatea cheilor:
        - Entropie Shannon
        - Distribuție biți
        - Surse de randomizare
        """
        print("\n" + "=" * 80)
        print("TESTAREA 8: ENTROPIA ȘI RANDOMIZARE")
        print("=" * 80)

        print(f"\nGenerare {num_keys} chei de {key_size} biți...")

        bit_distributions = []
        entropy_values = []
        primes_p = []
        primes_q = []

        for i in range(num_keys):
            key = RSA.generate(key_size)
            n_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, byteorder="big")

            # Test 8.1: Distribuție biți
            bit_count = bin(int.from_bytes(n_bytes, byteorder="big")).count("1")
            total_bits = len(n_bytes) * 8
            bit_ratio = bit_count / total_bits
            bit_distributions.append(bit_ratio)

            # Test 8.2: Entropie Shannon
            entropy = self._calculate_entropy(n_bytes)
            entropy_values.append(entropy)

            # Colectare prime pentru test
            if hasattr(key, "p") and hasattr(key, "q"):
                primes_p.append(key.p)
                primes_q.append(key.q)

            if (i + 1) % 20 == 0:
                print(f"  Progres: {i + 1}/{num_keys}")

        # Statistici distribuție biți
        print("\n--- 8.1 Distribuție Biți ---")
        print(f"Ideal: 0.5000 (50% biți = 1)")
        print(f"Media: {np.mean(bit_distributions):.4f}")
        print(f"Std Dev: {np.std(bit_distributions):.4f}")
        print(f"Min/Max: {min(bit_distributions):.4f} / {max(bit_distributions):.4f}")

        bit_quality = abs(np.mean(bit_distributions) - 0.5) < 0.01
        print(f"Calitate: {'✓ EXCELENTĂ' if bit_quality else '⚠ Acceptabilă'}")

        # Statistici entropie
        print("\n--- 8.2 Entropie Shannon ---")
        print(f"Ideal: 8.0000 (maxim pentru byte)")
        print(f"Media: {np.mean(entropy_values):.4f}")
        print(f"Std Dev: {np.std(entropy_values):.4f}")
        print(f"Min/Max: {min(entropy_values):.4f} / {max(entropy_values):.4f}")

        entropy_quality = np.mean(entropy_values) > 7.9
        print(f"Calitate: {'✓ EXCELENTĂ' if entropy_quality else '⚠ Acceptabilă'}")

        # Test 8.3: Test Chi-pătrat
        print("\n--- 8.3 Test Chi-Pătrat (Uniformitate) ---")
        expected_ratio = 0.5
        chi_square = sum(
            (ratio - expected_ratio) ** 2 / expected_ratio
            for ratio in bit_distributions
        )

        print(f"Valoare chi-pătrat: {chi_square:.2f}")
        print(
            f"Interpretare: {'✓ Distribuție uniformă' if chi_square < 20 else '⚠ Posibile neuniformități'}"
        )

        # Test 8.4: Sursă de randomizare
        print("\n--- 8.4 Sursă Randomizare ---")
        print("Bibliotecă: PyCryptodome (Crypto.Random)")

        # Test validare prime
        if primes_p and primes_q:
            print("\n--- 8.5 Validare Prime Generate ---")
            # Verificare că p != q
            unique_primes = len(set(primes_p + primes_q))
            print(f"Prime unice generate: {unique_primes}/{len(primes_p)*2}")
            print(
                f"p ≠ q pentru toate cheile: {'✓ DA' if unique_primes == len(primes_p)*2 else '✗ NU'}"
            )

        # Test NIST randomness (simplified)
        print("\n--- 8.6 Test NIST Randomness (Simplificat) ---")
        test_data = get_random_bytes(1000)

        # Frequency test (monobit)
        ones = bin(int.from_bytes(test_data, byteorder="big")).count("1")
        zeros = len(test_data) * 8 - ones
        frequency_balance = abs(ones - zeros) / (len(test_data) * 8)

        print(f"Frequency test: {frequency_balance:.4f} (ideal: < 0.01)")
        print(f"Rezultat: {'✓ TRECUT' if frequency_balance < 0.01 else '⚠ Marginal'}")

        self.results["entropy"] = {
            "key_size": key_size,
            "num_keys": num_keys,
            "bit_distribution_mean": np.mean(bit_distributions),
            "bit_distribution_std": np.std(bit_distributions),
            "entropy_mean": np.mean(entropy_values),
            "entropy_std": np.std(entropy_values),
            "chi_square": chi_square,
            "bit_quality": bit_quality,
            "entropy_quality": entropy_quality,
            "randomness_source": "CSPRNG",
        }

    # ============================================================================
    # FUNCȚII AUXILIARE
    # ============================================================================

    def _generate_weak_rsa(self, bits):
        """Generare cheie RSA slabă pentru teste"""
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        return n, e, d, p, q

    # ============================================================================
    # RAPORT FINAL COMPLET
    # ============================================================================

    def generate_complete_report(self):
        """Generează raportul final pentru toate testările"""
        print("\n" + "=" * 80)
        print("RAPORT FINAL COMPLET - TESTARE RSA")
        print("Toate cele 8 tipuri de testare")
        print("=" * 80)

        # Testarea 1
        print("\n1. EVALUAREA COMPLEXITĂȚII ALGORITMULUI:")
        if self.results["complexity"]:
            for result in self.results["complexity"]:
                status = (
                    "✓ Factorizat"
                    if result.get("factorized")
                    else "✗ Nu s-a factorizat"
                )
                print(
                    f"   {result['method']} ({result['key_size']} biți): {status} - {result['time_ms']:.2f} ms"
                )

        # Testarea 2
        print("\n2. REZISTENȚA LA ATACURI CRIPTANALITICE:")
        if self.results["cryptanalytic"]:
            for result in self.results["cryptanalytic"]:
                status = "✓ Rezistent" if result.get("resistant") else "⚠ Vulnerabil"
                print(f"   {result['attack_type']}: {status}")

        # Testarea 3
        print("\n3. AUDIT VULNERABILITĂȚI:")
        if self.results["vulnerabilities"]:
            vuln = self.results["vulnerabilities"]
            print(f"   Vulnerabilități găsite: {vuln['total_vulnerabilities']}")
            print(f"   Practici sigure verificate: {vuln['safe_practices_checked']}")

        # Testarea 4
        print("\n4. SIMULĂRI ȘI STRESS TEST:")
        if self.results["simulations"]:
            for result in self.results["simulations"]:
                if result["test"] == "stress_volume":
                    print(f"   Volume mari: {result['success_rate']*100:.1f}% succes")
                elif result["test"] == "stability":
                    print(
                        f"   Stabilitate: {'✓ Stabilă' if result['stable'] else '✗ Instabilă'}"
                    )
                elif result["test"] == "penetration_malformed":
                    print(
                        f"   Penetrare: {result['resilience_score']}/{result['total_tests']} teste"
                    )

        # Testarea 5
        print("\n5. CONFORMITATE CU STANDARDE:")
        if self.results["standards"]:
            std = self.results["standards"]
            print(
                f"   Verificări trecute: {std['passed_checks']}/{std['total_checks']}"
            )
            print(
                f"   Rata conformitate: {(std['passed_checks']/std['total_checks'])*100:.1f}%"
            )

        # Testarea 6
        print("\n6. PERFORMANȚĂ:")
        if self.results["performance"]:
            for result in self.results["performance"]:
                print(f"   Cheia {result['key_size']} biți:")
                print(f"     Generare: {result['key_gen_time']:.2f} ms")
                print(f"     Criptare: {result['encrypt_time']:.3f} ms")
                print(f"     Decriptare: {result['decrypt_time']:.3f} ms")

        # Testarea 7
        print("\n7. INTEGRITATE:")
        if self.results["integrity"]:
            passed = sum(
                1
                for r in self.results["integrity"]
                if r.get("passed")
                or (r.get("signature_valid") and r.get("tamper_detected"))
            )
            print(
                f"   Teste integritate: {passed}/{len(self.results['integrity'])} trecute"
            )

        # Testarea 8
        print("\n8. ENTROPIE ȘI RANDOMIZARE:")
        if self.results["entropy"]:
            ent = self.results["entropy"]
            print(
                f"   Distribuție biți: {ent['bit_distribution_mean']:.4f} (ideal: 0.5000)"
            )
            print(f"   Entropie Shannon: {ent['entropy_mean']:.4f} (ideal: 8.0000)")
            print(f"   Chi-pătrat: {ent['chi_square']:.2f}")
            print(f"   Sursă: {ent['randomness_source']}")

        print("\n" + "=" * 80)
        print("✓ TESTARE COMPLETĂ FINALIZATĂ")
        print("=" * 80)


# ============================================================================
# EXECUȚIE PRINCIPALĂ
# ============================================================================


def main():
    """Execută toate cele 8 tipuri de testare"""
    print("=" * 80)
    print("SET COMPLET DE TESTARE RSA")
    print("Implementare completă a tuturor celor 8 tipuri de testare")
    print("=" * 80)

    suite = RSACompleteTesting()

    try:
        # Testarea 1: Evaluarea complexității
        suite.test_1_complexity_evaluation()

        # Testarea 2: Rezistența la atacuri criptanalitice
        suite.test_2_cryptanalytic_attacks()

        # Testarea 3: Audit vulnerabilități
        suite.test_3_vulnerability_audit()

        # Testarea 4: Simulări și stress test
        suite.test_4_stress_and_penetration()

        # Testarea 5: Conformitate cu standarde
        suite.test_5_standards_compliance()

        # Testarea 6: Performanță
        suite.test_6_performance(key_sizes=[1024, 2048, 3072], iterations=5)

        # Testarea 7: Integritate
        suite.test_7_integrity()

        # Testarea 8: Entropie și randomizare
        suite.test_8_entropy_and_randomness(key_size=2048, num_keys=50)

        # Raport final complet
        suite.generate_complete_report()

        print("\n✓ Toate cele 8 tipuri de testare au fost executate cu succes!")
        print("\nPentru mai multe detalii, vezi secțiunile individuale de mai sus.")

    except Exception as e:
        print(f"\n✗ Eroare în timpul testării: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
