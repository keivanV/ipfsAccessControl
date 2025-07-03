import time
import os
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.secretutil import SecretUtil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import hashlib

# Initialize CP-ABE with SS512 pairing group (symmetric pairing)
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
util = SecretUtil(group, verbose=True)  # Enable verbose for debugging

# Setup CP-ABE parameters
(master_public_key, master_key) = cpabe.setup()

# Policy and user attributes (uppercase, at least 10 attributes)
policy = 'ATTR1'  # Simplified for testing
user_attributes = ['ATTR1', 'ATTR2', 'ATTR3', 'ATTR4', 'ATTR5', 'ATTR6', 'ATTR7', 'ATTR8', 'ATTR9', 'ATTR10']
user_key = cpabe.keygen(master_public_key, master_key, user_attributes)
print(f"User key: {user_key}")  # Debug: Inspect user key

# Test CP-ABE encryption/decryption independently
try:
    test_message = group.random(GT)
    test_ct = cpabe.encrypt(master_public_key, test_message, policy)
    print(f"Test ciphertext: {test_ct}")  # Debug: Inspect ciphertext
    test_decrypted = cpabe.decrypt(master_public_key, user_key, test_ct)
    print(f"Test CP-ABE: Encrypted {test_message}, Decrypted {test_decrypted}")
    if test_decrypted != test_message:
        print("Test CP-ABE decryption failed: mismatch")
        if test_decrypted is False:
            print("Decryption returned False, likely due to policy/attribute mismatch")
    else:
        print("Test CP-ABE decryption succeeded")
except Exception as e:
    print(f"Test CP-ABE failed: {e}")

# File sizes in KB
file_sizes_kb = [2, 4, 6, 8, 10]
chunk_size = 128  # bytes
num_runs = 1  # Number of runs for averaging

def generate_file(size_kb):
    """Generate a random file of size_kb KB."""
    return get_random_bytes(size_kb * 1024)

def aes_encrypt(data, key):
    """Encrypt data with AES."""
    try:
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, nonce, tag
    except Exception as e:
        print(f"AES encryption error: {e}")
        raise

def aes_decrypt(ciphertext, key, nonce, tag):
    """Decrypt data with AES."""
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print(f"AES decryption error: {e}")
        raise

def scenario_1(file_sizes_kb):
    """Scenario 1: Encrypt each file with AES, encrypt a GT element with CP-ABE."""
    times = []
    for size_kb in file_sizes_kb:
        total_time = 0
        for _ in range(num_runs):
            data = generate_file(size_kb)
            # Generate random GT element and derive AES key
            k = group.random(GT)
            k_bytes = group.serialize(k)
            aes_key = hashlib.sha256(k_bytes).digest()[:16]
            
            # Measure AES encryption time
            start_time = time.time()
            ciphertext, nonce, tag = aes_encrypt(data, aes_key)
            aes_enc_time = time.time() - start_time
            
            # Measure CP-ABE encryption of k
            start_time = time.time()
            ct = cpabe.encrypt(master_public_key, k, policy)
            cpabe_enc_time = time.time() - start_time
            
            total_time += aes_enc_time + cpabe_enc_time
            
            # Verify decryption (for correctness, not timed)
            try:
                decrypted_k = cpabe.decrypt(master_public_key, user_key, ct)
                if decrypted_k is False:
                    print(f"Scenario 1: Ciphertext: {ct}")  # Debug
                    raise Exception("CP-ABE decryption failed in Scenario 1: Returned False")
                decrypted_k_bytes = group.serialize(decrypted_k)
                decrypted_aes_key = hashlib.sha256(decrypted_k_bytes).digest()[:16]
                decrypted_data = aes_decrypt(ciphertext, decrypted_aes_key, nonce, tag)
                if decrypted_data != data:
                    raise Exception("AES decryption failed in Scenario 1")
            except Exception as e:
                print(f"Decryption error in Scenario 1: {e}")
                raise
            
        times.append(total_time / num_runs)
    return times

def scenario_2(file_sizes_kb):
    """Scenario 2: Split file into 512-byte chunks, encrypt each with AES, encrypt GT elements with CP-ABE."""
    times = []
    for size_kb in file_sizes_kb:
        total_time = 0
        for _ in range(num_runs):
            data = generate_file(size_kb)
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            run_time = 0
            
            for chunk in chunks:
                # Generate random GT element and derive AES key
                k = group.random(GT)
                k_bytes = group.serialize(k)
                aes_key = hashlib.sha256(k_bytes).digest()[:16]
                
                # Measure AES encryption time for chunk
                start_time = time.time()
                ciphertext, nonce, tag = aes_encrypt(chunk, aes_key)
                aes_enc_time = time.time() - start_time
                
                # Measure CP-ABE encryption of k
                start_time = time.time()
                ct = cpabe.encrypt(master_public_key, k, policy)
                cpabe_enc_time = time.time() - start_time
                
                run_time += aes_enc_time + cpabe_enc_time
                
                # Verify decryption (for correctness, not timed)
                try:
                    decrypted_k = cpabe.decrypt(master_public_key, user_key, ct)
                    if decrypted_k is False:
                        print(f"Scenario 2: Ciphertext: {ct}")  # Debug
                        raise Exception("CP-ABE decryption failed in Scenario 2: Returned False")
                    decrypted_k_bytes = group.serialize(decrypted_k)
                    decrypted_aes_key = hashlib.sha256(decrypted_k_bytes).digest()[:16]
                    decrypted_chunk = aes_decrypt(ciphertext, decrypted_aes_key, nonce, tag)
                    if decrypted_chunk != chunk:
                        raise Exception("AES decryption failed in Scenario 2")
                except Exception as e:
                    print(f"Decryption error in Scenario 2: {e}")
                    raise
                
            total_time += run_time
        
        times.append(total_time / num_runs)
    return times

# Run both scenarios
try:
    times_scenario_1 = scenario_1(file_sizes_kb)
    times_scenario_2 = scenario_2(file_sizes_kb)
except Exception as e:
    print(f"Error running scenarios: {e}")
    exit(1)

# Plot results
plt.figure(figsize=(10, 6))
plt.plot(file_sizes_kb, times_scenario_1, marker='o', label='Scenario 1: Single AES + CP-ABE')
plt.plot(file_sizes_kb, times_scenario_2, marker='s', label='Scenario 2: Chunked AES + CP-ABE')
plt.xlabel('File Size (KB)')
plt.ylabel('Average Encryption Time (seconds)')
# plt.title('Encryption Time vs File Size for CP-ABE Scenarios')
plt.legend()
plt.grid(True)
plt.savefig('encryption_times.png')
plt.show()