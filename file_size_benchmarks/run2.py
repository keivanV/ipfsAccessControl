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

# Policy and user attributes (uppercase, at least 12 attributes for scenario_2)
policy = '(ATTR1 AND ATTR2)'  # Policy for scenario 1
user_attributes = ['ATTR1', 'ATTR2', 'ATTR3', 'ATTR4', 'ATTR5', 'ATTR6', 'ATTR7', 'ATTR8', 'ATTR9', 'ATTR10', 'ATTR11', 'ATTR12']
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

# Parameters
file_count_list = [2, 4, 6, 8, 10 , 12 , 14]  # Number of 1KB files for scenario 1
chunk_size = 128  # bytes 
num_runs = 1  # Number of runs for averaging
attr_list = [2, 4, 6, 8, 10, 12]  # Number of attributes for scenario_2
file_count_list_s2 = [2, 4, 6, 8, 10, 12,14]  # Number of files for scenario_2
fixed_file_size_kb = 1  # Fixed file size of 1KB

def generate_file():
    """Generate a random 1KB file."""
    return get_random_bytes(fixed_file_size_kb * 1024)

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

def generate_policy(attr_count):
    """Generate a policy with attr_count attributes, e.g., (ATTR1 AND ATTR2 AND ...)."""
    attributes = [f"ATTR{i+1}" for i in range(attr_count)]
    return "(" + " AND ".join(attributes) + ")"

def scenario_1(file_count_list):
    """Scenario 1: Encrypt each 1KB file with AES, encrypt a GT element with CP-ABE."""
    times = []
    for file_count in file_count_list:
        total_time = 0
        for _ in range(num_runs):
            run_time = 0
            for _ in range(file_count):
                data = generate_file()
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
                
                run_time += aes_enc_time + cpabe_enc_time
                
                # Verify decryption (for correctness, not timed)
                try:
                    decrypted_k = cpabe.decrypt(master_public_key, user_key, ct)
                    if decrypted_k is False:
                        print(f"Scenario 1: Ciphertext: {ct}")
                        raise Exception("CP-ABE decryption failed in Scenario 1: Returned False")
                    decrypted_k_bytes = group.serialize(decrypted_k)
                    decrypted_aes_key = hashlib.sha256(decrypted_k_bytes).digest()[:16]
                    decrypted_data = aes_decrypt(ciphertext, decrypted_aes_key, nonce, tag)
                    if decrypted_data != data:
                        raise Exception("AES decryption failed in Scenario 1")
                except Exception as e:
                    print(f"Decryption error in Scenario 1: {e}")
                    raise
            
            total_time += run_time
        
        times.append((total_time / num_runs) * 1000)
    return times

def scenario_2(attr_list, file_count_list):
    """Scenario 2: Encrypt file_count 1KB files with policies of attr_count attributes, each file chunked."""
    times = []
    for attr_count in attr_list:
        # Generate policy for attr_count attributes
        local_policy = generate_policy(attr_count)
        print(f"Scenario 2: Testing policy with {attr_count} attributes: {local_policy}")
        attr_times = []
        for file_count in file_count_list:
            total_time = 0
            for _ in range(num_runs):
                run_time = 0
                for _ in range(file_count):
                    data = generate_file()
                    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
                    
                    for chunk in chunks:
                        # Generate random GT element and derive AES key
                        k = group.random(GT)
                        k_bytes = group.serialize(k)
                        aes_key = hashlib.sha256(k_bytes).digest()[:16]
                        
                        # Measure AES encryption time
                        start_time = time.time()
                        ciphertext, nonce, tag = aes_encrypt(chunk, aes_key)
                        aes_enc_time = time.time() - start_time
                        
                        # Measure CP-ABE encryption of k
                        start_time = time.time()
                        ct = cpabe.encrypt(master_public_key, k, local_policy)
                        cpabe_enc_time = time.time() - start_time
                        
                        run_time += aes_enc_time + cpabe_enc_time
                        
                        # Verify decryption (for correctness, not timed)
                        try:
                            decrypted_k = cpabe.decrypt(master_public_key, user_key, ct)
                            if decrypted_k is False:
                                print(f"Scenario 2: Ciphertext for {attr_count} attrs, {file_count} files: {ct}")
                                raise Exception("CP-ABE decryption failed in Scenario 2: Returned False")
                            decrypted_k_bytes = group.serialize(decrypted_k)
                            decrypted_aes_key = hashlib.sha256(decrypted_k_bytes).digest()[:16]
                            decrypted_data = aes_decrypt(ciphertext, decrypted_aes_key, nonce, tag)
                            if decrypted_data != chunk:
                                raise Exception("AES decryption failed in Scenario 2")
                        except Exception as e:
                            print(f"Decryption error in Scenario 2: {e}")
                            raise
                
                total_time += run_time
            
            attr_times.append( (total_time / num_runs) * 1000)
        times.append(attr_times)
    return times

# Run scenarios
try:
    times_scenario_1 = scenario_1(file_count_list)
    times_scenario_2 = scenario_2(attr_list, file_count_list_s2)
except Exception as e:
    print(f"Error running scenarios: {e}")
    exit(1)

# Plot results
plt.figure(figsize=(12, 8))

# Plot Scenario 1
plt.plot(file_count_list, times_scenario_1, marker='o', label='Scenario 1: Single AES + CP-ABE')

# Plot Scenario 2 (one line per attribute count)
for i, attr_count in enumerate(attr_list):
    plt.plot(file_count_list_s2, times_scenario_2[i], marker='^', label=f'Scenario 2: {attr_count} Attributes')

plt.xlabel('File Count (1KB files)')
plt.ylabel('Average Encryption Time (ms)')
plt.legend()
plt.grid(True)
plt.savefig('encryption_times.pdf')
plt.show()