import random
from math import ceil
from decimal import Decimal
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import matplotlib.pyplot as plt
import numpy as np

# Use a large prime for FIELD_SIZE
FIELD_SIZE = 2**127 - 1  # Mersenne prime for better arithmetic properties

def mod_inverse(a, m):
    """Calculate the modular inverse of a modulo m using the extended Euclidean algorithm."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m

def reconstruct_secret(shares):
    """Reconstruct the secret using Lagrange interpolation with modular arithmetic."""
    sums = 0
    for j, share_j in enumerate(shares):
        xj, yj = share_j
        prod = 1
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                # Compute (xi * (xi - xj)^(-1)) mod FIELD_SIZE
                denominator = (xi - xj) % FIELD_SIZE
                if denominator == 0:
                    raise ValueError("Duplicate x values in shares")
                prod = (prod * xi * mod_inverse(denominator, FIELD_SIZE)) % FIELD_SIZE
        prod = (prod * yj) % FIELD_SIZE
        sums = (sums + prod) % FIELD_SIZE
    return sums

def polynom(x, coefficients):
    """Evaluate polynomial at x with modular arithmetic."""
    point = 0
    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
        point = (point + (pow(x, coefficient_index, FIELD_SIZE) * coefficient_value)) % FIELD_SIZE
    return point

def coeff(t, secret):
    """Generate coefficients for a polynomial of degree t-1 with constant term secret."""
    coeff = [random.randrange(0, FIELD_SIZE) for _ in range(t - 1)]
    coeff.append(secret % FIELD_SIZE)  # Ensure secret is within FIELD_SIZE
    return coeff

def generate_shares(n, m, secret):
    """Generate n shares with threshold m using Shamir's Secret Sharing."""
    coefficients = coeff(m, secret)
    shares = []
    used_x = set()  # Track used x values to ensure uniqueness
    for _ in range(n):
        x = random.randrange(1, FIELD_SIZE)
        while x in used_x:  # Ensure unique x
            x = random.randrange(1, FIELD_SIZE)
        used_x.add(x)
        shares.append((x, polynom(x, coefficients)))
    return shares

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_share(share, public_key):
    x, y = share
    share_bytes = f"{x},{y}".encode()
    ciphertext = public_key.encrypt(
        share_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_share(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    x, y = map(int, plaintext.decode().split(','))
    return (x, y)

def benchmark_shamir_rsa(shares_counts, secret):
    results = []
    
    for n in shares_counts:
        print(f"\nBenchmarking with {n} shares (nodes)")
        nodes = n
        key_pairs = [generate_rsa_keys() for _ in range(nodes)]
        
        for threshold_percent in [1.0, 0.8, 0.5, 0.3]:
            t = max(1, ceil(n * threshold_percent))
            
            start_time = time.time()
            shares = generate_shares(n, t, secret)
            encrypted_shares = []
            for i, share in enumerate(shares):
                encrypted_share = encrypt_share(share, key_pairs[i][1])
                encrypted_shares.append((encrypted_share, i))
            encryption_time = time.time() - start_time
            
            start_time = time.time()
            decrypted_shares = []
            selected_shares = random.sample(encrypted_shares, t)
            for encrypted_share, key_index in selected_shares:
                decrypted_share = decrypt_share(encrypted_share, key_pairs[key_index][0])
                decrypted_shares.append(decrypted_share)
            
            reconstructed_secret = reconstruct_secret(decrypted_shares)
            decryption_time = time.time() - start_time
            
            success = reconstructed_secret == secret
            
            results.append({
                'shares': n,
                'threshold': f"{int(threshold_percent*100)}% ({t} shares)",
                'encryption_time': encryption_time,  # Fixed typo
                'decryption_time': decryption_time,
                'success': success
            })
            
            print(f"Threshold {threshold_percent*100}% ({t} shares):")
            print(f"  Encryption time: {encryption_time:.4f} seconds")
            print(f"  Decryption time: {decryption_time:.4f} seconds")
            print(f"  Reconstruction successful: {success}")
    
    return results

def plot_results(results, shares_counts):
    thresholds = ['100% ', '80% ', '50% ', '30% ']  # Trailing space to match threshold string
    colors = ['b', 'g', 'r', 'c']
    # Descriptive labels for the legend
    legend_labels = [
        'all nodes participate',
        '80% of nodes participate',
        '50% of nodes participate',
        '30% of nodes participate'
    ]
    
    enc_times = {t: [] for t in thresholds}
    dec_times = {t: [] for t in thresholds}
    
    for n in shares_counts:
        for result in results:
            if result['shares'] == n:
                # Extract the percentage part including the trailing space
                threshold = result['threshold'].split('(')[0].strip() + ' '
                # Convert times from seconds to milliseconds
                enc_times[threshold].append(result['encryption_time'] * 1000)
                dec_times[threshold].append(result['decryption_time'] * 1000)
    
    plt.figure(figsize=(10, 6))
    for threshold, color, label in zip(thresholds, colors, legend_labels):
        plt.plot(shares_counts, enc_times[threshold], marker='o', label=f'Encryption {label}', color=color)
    plt.xlabel('Number of Shares')
    plt.ylabel('Time (milliseconds)')
    plt.title('Encryption Time vs Number of Shares')
    plt.legend(fontsize=12)  # Increased legend font size
    plt.grid(True)
    plt.xticks(shares_counts)
    plt.savefig('encryption_times_ms.png')
    plt.close()
    
    plt.figure(figsize=(10, 6))
    for threshold, color, label in zip(thresholds, colors, legend_labels):
        plt.plot(shares_counts, dec_times[threshold], marker='o', label=f'Decryption {label}', color=color)
    plt.xlabel('Number of Shares')
    plt.ylabel('Time (milliseconds)')
    plt.title('Decryption Time vs Number of Shares')
    plt.legend(fontsize=12)  # Increased legend font size
    plt.grid(True)
    plt.xticks(shares_counts)
    plt.savefig('decryption_times_ms.png')
    plt.close()


    
if __name__ == '__main__':
    secret = 1234
    print(f"Original Secret: {secret}")
    shares_counts = [10, 40, 80, 120, 200, 300 , 500 , 1000]
    
    results = benchmark_shamir_rsa(shares_counts, secret)
    
    print("\nBenchmark Summary:")
    print("Shares | Threshold | Encryption Time (s) | Decryption Time (s) | Success")
    print("-" * 70)
    for result in results:
        print(f"{result['shares']:6} | {result['threshold']:9} | {result['encryption_time']:18.4f} | {result['decryption_time']:18.4f} | {result['success']}")
    
    plot_results(results, shares_counts)
    print("\nPlots saved as 'encryption_times.png' and 'decryption_times.png'")