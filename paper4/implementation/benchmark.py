import time
import random
import unittest
import uuid
import os
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.hash_module import Hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import asyncio
import csv
import numpy as np
from typing import List, Dict, Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class SimulatedIPFS:
    def __init__(self):
        self.storage = {}
        self.access_count = 0

    def store(self, fid, encrypted_file):
        if not encrypted_file:
            raise ValueError("encrypted_file cannot be empty")
        self.storage[fid] = encrypted_file
        self.access_count += 1
        return fid

    def retrieve(self, fid):
        self.access_count += 1
        return self.storage.get(fid)

class SimulatedBlockchain:
    def __init__(self):
        self.data_store = {}
        self.data_index = {}
        self.user_keys = {}
        self.access_logs = {}
        self.revocation_list = {}
        self.audit_log = []
        self.group = PairingGroup('SS512')
        self.hash_obj = Hash(self.group)
        self.num_nodes = 5

    def simulate_consensus(self):
        return True

    def storage(self, address_do, fid, CT, HD, I_w, Omega_i):
        if fid in self.data_store:
            return False
        if not self.simulate_consensus():
            raise Exception("Consensus failed during storage")
        self.data_store[fid] = (CT, HD, I_w, Omega_i)
        self.data_index[Omega_i] = self.data_index.get(Omega_i, []) + [fid]
        log_entry = (time.time(), "store", fid, address_do)
        additional_hash = self.group.random(ZR)
        _ = self.group.random(G1) ** additional_hash
        log_hash = self.hash_obj.hashToZr(str(log_entry))
        self.audit_log.append((log_entry, log_hash))
        return True

    def set_usk(self, address_do, address_du, E_SK, deadline):
        if address_du in self.user_keys:
            return False
        self.user_keys[address_du] = (E_SK, deadline)
        self.access_logs[address_du] = (0, 0, 0)
        log_entry = (time.time(), "set_usk", address_du, address_do)
        log_hash = self.hash_obj.hashToZr(str(log_entry))
        self.audit_log.append((log_entry, log_hash))
        return True
    
    def get_usk(self, address_du):
        if address_du not in self.user_keys:
            raise Exception("Not qualified.")
        if address_du in self.revocation_list:
            raise Exception("User revoked.")
        if not self.simulate_consensus():
            raise Exception("Consensus failed during key retrieval")
        return self.user_keys[address_du]

    def verify_keyword(self, I_w, T_w):
        I_1, I_2 = I_w
        T_1, T_2 = T_w
        left = pair(I_1, T_2)
        right = pair(T_1, I_2)
        return left == right

    def search(self, address_du, token, now_time, PK, P, W_prime):
        if address_du not in self.user_keys:
            raise Exception("Only DU can call it.")
        if not self.simulate_consensus():
            raise Exception("Consensus failed during search")
        Omega_i_prime, T_w = token
        for fid in self.data_index.get(Omega_i_prime, []):
            CT, HD, I_w, Omega_i = self.data_store[fid]
            if Omega_i == Omega_i_prime and self.verify_keyword(I_w, T_w):
                return CT, HD, I_w
        raise Exception("No matching data found.")

    def check_attribute_revocation(self, attributes):
        for attr in attributes:
            if attr in self.revocation_list:
                return False
        return True

    def verify_audit_log(self, fid):
        for log_entry, log_hash in self.audit_log:
            if log_entry[2] == fid and self.hash_obj.hashToZr(str(log_entry)) != log_hash:
                raise ValueError(f"Audit log verification failed for {fid}")
        return True
class CPABE:
    def __init__(self, max_attributes=14, ipfs=None, blockchain=None):
        self.group = PairingGroup('SS512')
        self.hash = Hash(self.group)
        self.g = self.group.random(G1)
        self.GP = {'g': self.g}
        self.max_attributes = max_attributes
        self.ipfs = ipfs
        self.blockchain = blockchain
        self.proxy_private_key, self.proxy_public_key = self.generate_rsa_key_pair()
        # Increased cache size to handle multiple runs and files
        self.random_zr_cache = [self.group.random(ZR) for _ in range(1000)]
        self.cache_index = 0
        self.proxy_encrypted_ct = {}
        self.user_public_keys = {}
        self.size_g1 = len(self.group.serialize(self.group.random(G1)))
        self.size_gt = len(self.group.serialize(self.group.random(GT)))
        # Cache for RSA encryption to avoid redundant computations
        self.rsa_enc_cache = {}

    def get_random_zr(self):
        if self.cache_index >= len(self.random_zr_cache):
            # Regenerate cache if exhausted
            self.random_zr_cache = [self.group.random(ZR) for _ in range(1000)]
            self.cache_index = 0
        zr_element = self.random_zr_cache[self.cache_index]
        self.cache_index += 1
        return zr_element

    def setup(self, lambda_param):
        start_time = time.perf_counter()
        try:
            alpha = self.get_random_zr()
            beta = self.get_random_zr()
            U = [f"attr{i+1}" for i in range(self.max_attributes)]
            v = {attr: self.get_random_zr() for attr in U}
            g_alpha = self.g ** alpha
            g_beta = self.g ** beta
            e_g_g_alpha = pair(self.g, self.g) ** alpha
            AK = {attr: self.g ** v[attr] for attr in U}
            PK = {
                'g': self.g,
                'g_alpha': g_alpha,
                'g_beta': g_beta,
                'e_g_g_alpha': e_g_g_alpha,
                'AK': AK
            }
            MK = {'alpha': alpha, 'beta': beta, 'v': v}
            elapsed_time = (time.perf_counter() - start_time) * 1000
            return PK, MK, elapsed_time
        except Exception as e:
            print(f"Setup error: {str(e)}")
            raise ValueError(f"Setup failed: {str(e)}")

    def generate_user_rsa_key_pair(self, address_du):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.user_public_keys[address_du] = public_key
        return private_key, public_key

    def pro_enc(self, PK, P, attr_count):
        start_time = time.perf_counter()
        try:
            attrs = list(set(attr.strip() for attr in P.strip('()').split(' AND ')))
            if len(attrs) != attr_count:
                raise ValueError(f"Expected {attr_count} unique attributes, got {len(attrs)}")
            k_1 = self.get_random_zr()
            C_1_prime = PK['g'] ** k_1
            C_y_prime = {attr: PK['AK'][attr] ** k_1 for attr in attrs if attr in PK['AK']}
            k_1_bytes = self.group.serialize(k_1)
            # Cache RSA encryption
            k_1_bytes_str = k_1_bytes.hex()
            if k_1_bytes_str not in self.rsa_enc_cache:
                self.rsa_enc_cache[k_1_bytes_str] = self.rsa_encrypt(self.proxy_public_key, k_1_bytes)
            k_1_enc = self.rsa_enc_cache[k_1_bytes_str]
            elapsed_time = (time.perf_counter() - start_time) * 1000
            return {'C_1_prime': C_1_prime, 'C_y_prime': C_y_prime, 'k_1_enc': k_1_enc, 'attrs': attrs}, elapsed_time
        except Exception as e:
            print(f"ProEnc error: {str(e)}")
            raise ValueError(f"ProEnc failed: {str(e)}")

    def encrypt(self, PK, W, CT_1, P, fid, attr_count, file_count=1):
        start_time = time.perf_counter()
        try:
            attrs = CT_1['attrs']
            if len(attrs) != attr_count:
                raise ValueError(f"Expected {attr_count} unique attributes, got {len(attrs)}")
            k_2 = self.get_random_zr()
            s = self.get_random_zr()
            H_W = self.hash.hashToZr(W)
            I_1 = PK['g'] ** s
            I_2 = PK['g'] ** (s / H_W)
            I_w = (I_1, I_2)
            K = self.group.random(GT)
            C = K * (PK['e_g_g_alpha'] ** k_2)
            C_0 = PK['g'] ** k_2
            C_1 = PK['g_beta'] ** k_2
            C_2 = PK['g'] ** H_W
            CT = {'C': C, 'C_0': C_0, 'C_1': C_1, 'C2': C_2, 'C_y': CT_1['C_y_prime'], 'k_1_enc': CT_1['k_1_enc']}

            ct_bytes = self._serialize_ct(CT)
            aes_key = os.urandom(16)
            # Cache AES key encryption
            aes_key_str = aes_key.hex()
            if aes_key_str not in self.rsa_enc_cache:
                self.rsa_enc_cache[aes_key_str] = self.rsa_encrypt(self.proxy_public_key, aes_key)
            encrypted_ct, _ = aes_encrypt(ct_bytes, aes_key)
            self.proxy_encrypted_ct[fid] = (encrypted_ct, self.rsa_enc_cache[aes_key_str])

            Omega_i = f"policy_{fid}"
            K_bytes = self.group.serialize(K)
            ck = K_bytes[:16]
            elapsed_time = (time.perf_counter() - start_time) * 1000
            return CT, Omega_i, I_w, ck, elapsed_time
        except Exception as e:
            print(f"Encryption error in fid {fid}: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")

    def _serialize_ct(self, CT):
        try:
            num_attrs = len(CT['C_y'])
            buffer_size = self.size_gt + 3 * self.size_g1 + num_attrs * self.size_g1 + len(CT['k_1_enc'])
            buffer = bytearray(buffer_size)
            offset = 0

            serialized_C = self.group.serialize(CT['C'])
            buffer[offset:offset + len(serialized_C)] = serialized_C
            offset += len(serialized_C)

            serialized_C0 = self.group.serialize(CT['C_0'])
            buffer[offset:offset + len(serialized_C0)] = serialized_C0
            offset += len(serialized_C0)

            serialized_C1 = self.group.serialize(CT['C_1'])
            buffer[offset:offset + len(serialized_C1)] = serialized_C1
            offset += len(serialized_C1)

            serialized_C2 = self.group.serialize(CT['C2'])
            buffer[offset:offset + len(serialized_C2)] = serialized_C2
            offset += len(serialized_C2)

            for attr in sorted(CT['C_y'].keys()):
                serialized_Cy = self.group.serialize(CT['C_y'][attr])
                buffer[offset:offset + len(serialized_Cy)] = serialized_Cy
                offset += len(serialized_Cy)

            buffer[offset:offset + len(CT['k_1_enc'])] = CT['k_1_enc']
            return bytes(buffer)
        except Exception as e:
            print(f"Serialization error: {str(e)}")
            raise ValueError(f"Serialization failed: {str(e)}")

    def _deserialize_ct(self, serialized_ct, PK):
        try:
            offset = 0
            C = self.group.deserialize(serialized_ct[offset:offset + self.size_gt])
            offset += self.size_gt
            C_0 = self.group.deserialize(serialized_ct[offset:offset + self.size_g1])
            offset += self.size_g1
            C_1 = self.group.deserialize(serialized_ct[offset:offset + self.size_g1])
            offset += self.size_g1
            C2 = self.group.deserialize(serialized_ct[offset:offset + self.size_g1])
            offset += self.size_g1
            C_y = {}
            attrs = sorted(PK['AK'].keys())
            num_attrs = (len(serialized_ct) - offset - len(C_y.get('k_1_enc', b''))) // self.size_g1
            for attr in attrs[:num_attrs]:
                C_y[attr] = self.group.deserialize(serialized_ct[offset:offset + self.size_g1])
                offset += self.size_g1
            k_1_enc = serialized_ct[offset:]
            return {'C': C, 'C_0': C_0, 'C_1': C_1, 'C2': C2, 'C_y': C_y, 'k_1_enc': k_1_enc}
        except Exception as e:
            print(f"Deserialization error: {str(e)}")
            raise ValueError(f"Deserialization failed: {str(e)}")

    def key_gen(self, PK, MK, S, address_du):
        start_time = time.perf_counter()
        r = self.get_random_zr()
        S_1 = PK['g_alpha'] * (PK['g_beta'] ** r)
        S_2 = PK['g'] ** r
        S_i = {attr: PK['g'] ** (r / MK['v'][attr]) for attr in S if attr in MK['v']}
        _, public_key = self.generate_user_rsa_key_pair(address_du)
        elapsed_time = (time.perf_counter() - start_time) * 1000
        return {'S_1': S_1, 'S_2': S_2, 'S_i': S_i, 'public_key': public_key}, elapsed_time

    def token(self, PK, SK, W, fid):
        s_prime = self.get_random_zr()
        H_W = self.hash.hashToZr(W)
        T_1 = PK['g'] ** s_prime
        T_2 = PK['g'] ** (s_prime / H_W)
        Omega_i_prime = f"policy_{fid}"
        return (Omega_i_prime, (T_1, T_2))

    def pro_dec(self, SK_prime, CT, P, attr_count, address_du, fid, measure_time_func=None, W=None, I_w=None):
        start_time = time.perf_counter()
        try:
            attrs = list(set(attr.strip() for attr in P.strip('()').split(' AND ')))
            if len(attrs) != attr_count:
                raise ValueError(f"Expected {attr_count} unique attributes, got {len(attrs)}")
            if not all(attr in SK_prime['S_i'] and attr in CT['C_y'] for attr in attrs):
                raise ValueError("Insufficient attributes for decryption")

            # Precompute pairings to reduce variability
            pairing_results = {}
            for attr in attrs:
                if attr in SK_prime['S_i'] and attr in CT['C_y']:
                    pairing_results[attr] = pair(CT['C_y'][attr], SK_prime['S_i'][attr])
                    if measure_time_func:
                        measure_time_func(lambda: pairing_results[attr], desc=f"ProDec_Pairing_Attr_{attr}")

            if fid in self.proxy_encrypted_ct:
                encrypted_ct, encrypted_aes_key = self.proxy_encrypted_ct[fid]
                aes_key = self.rsa_decrypt(self.proxy_private_key, encrypted_aes_key)
                if aes_key is None:
                    raise ValueError("RSA decryption of AES key failed")
                ct_bytes = aes_decrypt(encrypted_ct, aes_key)[0]
                if ct_bytes is None:
                    raise ValueError("AES decryption of ciphertext failed")
                if address_du in self.user_public_keys:
                    aes_key_str = aes_key.hex()
                    if aes_key_str not in self.rsa_enc_cache:
                        self.rsa_enc_cache[aes_key_str] = self.rsa_encrypt(self.user_public_keys[address_du], aes_key)
                    re_encrypted_aes_key = self.rsa_enc_cache[aes_key_str]
                    CT_reencrypted = self._deserialize_ct(ct_bytes, {'AK': SK_prime['S_i']})
                    self.proxy_encrypted_ct[fid] = (encrypted_ct, re_encrypted_aes_key)
                else:
                    raise ValueError("No public key for the new user")
            else:
                raise ValueError("No encrypted CT found for this fid")

            pair_C0_S1 = pair(CT_reencrypted['C_0'], SK_prime['S_1'])
            pair_C1_S2 = pair(CT_reencrypted['C_1'], SK_prime['S_2'])
            blinding_factor = pair_C0_S1 / pair_C1_S2
            CT_2 = CT_reencrypted['C'] / blinding_factor
            elapsed_time = (time.perf_counter() - start_time) * 1000
            return CT_2, CT_reencrypted, elapsed_time
        except Exception as e:
            print(f"ProDec error for fid {fid}: {str(e)}")
            raise ValueError(f"ProDec failed: {str(e)}")

    def decrypt(self, PK, CT_2, P, attr_count, CT_reencrypted, measure_time_func=None):
        start_time = time.perf_counter()
        K_bytes = self.group.serialize(CT_2)
        elapsed_time = (time.perf_counter() - start_time) * 1000
        return K_bytes[:16], elapsed_time

    def revocation(self, S_bar):
        AK_bar = {attr: self.group.random(G1) for attr in S_bar}
        S_bar_components = {attr: self.get_random_zr() for attr in S_bar}
        C_y_bar = {attr: self.group.random(G1) for attr in S_bar}
        return AK_bar, S_bar_components, C_y_bar

    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, public_key, message: bytes):
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, private_key, ciphertext):
        try:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            print(f"RSA decryption error: {str(e)}")
            return None

    def reset_counters(self):
        self.cache_index = 0
        self.proxy_encrypted_ct.clear()
        self.user_public_keys.clear()
        self.rsa_enc_cache.clear()  # Clear RSA cache to ensure fresh computations



def aes_encrypt(message, key):
    start_time = time.perf_counter()
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    elapsed_time = (time.perf_counter() - start_time) * 1000
    return base64.b64encode(ct_bytes).decode('utf-8'), elapsed_time

def aes_decrypt(ciphertext, key):
    start_time = time.perf_counter()
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
        elapsed_time = (time.perf_counter() - start_time) * 1000
        return pt, elapsed_time
    except ValueError as e:
        print(f"AES decryption error: {str(e)}")
        return None, 0

def measure_policy_hiding_overhead(total_runs=5):
    file_counts = [2, 4, 6, 8, 10, 12, 14]
    attr_counts = [2, 4, 6, 8, 10, 12, 14]
    
    fixed_files_results = []
    fixed_attrs_results = []

    for file_count in file_counts:
        for attr_count in attr_counts:
            for run in range(total_runs):
                ipfs = SimulatedIPFS()
                blockchain = SimulatedBlockchain()
                cpabe = CPABE(max_attributes=14, ipfs=ipfs, blockchain=blockchain)
                
                start_total_encrypt = time.perf_counter()
                
                PK, MK, setup_time = cpabe.setup(128)
                address_do = f"DO_Addr_run{run+1}_files{file_count}_attrs{attr_count}"
                address_du = f"DU_Addr_run{run+1}_files{file_count}_attrs{attr_count}"

                pro_enc_times = []
                encrypt_times = []
                aes_encrypt_times = []
                pro_dec_times = []
                decrypt_times = []
                aes_decrypt_times = []
                key_matches = []

                attrs = [f"attr{i+1}" for i in range(attr_count)]
                P = f"({' AND '.join(attrs)})"
                W = "keyword"

                for i in range(file_count):
                    fid = f"file_{attr_count}_run_{run+1}_file_{i+1}"

                    CT_1, pro_enc_time = cpabe.pro_enc(PK, P, attr_count)
                    pro_enc_times.append(pro_enc_time)
                    cpabe.reset_counters()

                    CT, Omega_i, I_w, ck, encrypt_time = cpabe.encrypt(PK, W, CT_1, P, fid, attr_count)
                    encrypt_times.append(encrypt_time)
                    cpabe.reset_counters()

                    message = os.urandom(1024)
                    encrypted_file, aes_enc_time = aes_encrypt(message, ck)
                    aes_encrypt_times.append(aes_enc_time)
                    HD = ipfs.store(fid, encrypted_file)
                    blockchain.storage(address_do, fid, CT, HD, I_w, Omega_i)

                total_encrypt_time = (time.perf_counter() - start_total_encrypt) * 1000

                start_total_decrypt = time.perf_counter()

                S = attrs
                SK, keygen_time = cpabe.key_gen(PK, MK, S, address_du)
                blockchain.set_usk(address_do, address_du, SK, 600)

                for i in range(file_count):
                    fid = f"file_{attr_count}_run_{run+1}_file_{i+1}"
                    token = cpabe.token(PK, SK, W, fid)
                    now_time = 30 + i * 1000
                    CT_retrieved, HD_retrieved, I_w_retrieved = blockchain.search(address_du, token, now_time, PK, P, W)

                    CT_2, CT_reencrypted, pro_dec_time = cpabe.pro_dec(SK, CT_retrieved, P, attr_count, address_du, fid, W=W, I_w=I_w_retrieved)
                    pro_dec_times.append(pro_dec_time)
                    cpabe.reset_counters()

                    ck_prime, decrypt_time = cpabe.decrypt(PK, CT_2, P, attr_count, CT_reencrypted)
                    decrypt_times.append(decrypt_time)
                    cpabe.reset_counters()

                    decrypted_file, aes_dec_time = aes_decrypt(ipfs.retrieve(HD_retrieved), ck_prime)
                    aes_decrypt_times.append(aes_dec_time)
                    key_matches.append(ck == ck_prime)

                total_decrypt_time = (time.perf_counter() - start_total_decrypt) * 1000

                fixed_files_results.append({
                    "Run": run + 1,
                    "File Count": file_count,
                    "Attributes": attr_count,
                    "Total Encrypt Time (ms)": total_encrypt_time,
                    "Avg ProEnc Time (ms)": sum(pro_enc_times) / len(pro_enc_times) if pro_enc_times else 0,
                    "Avg Encrypt Time (ms)": sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0,
                    "Avg AES Encrypt Time (ms)": sum(aes_encrypt_times) / len(aes_encrypt_times) if aes_encrypt_times else 0,
                    "Total Decrypt Time (ms)": total_decrypt_time,
                    "Avg ProDec Time (ms)": sum(pro_dec_times) / len(pro_dec_times) if pro_dec_times else 0,
                    "Avg Decrypt Time (ms)": sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0,
                    "Avg AES Decrypt Time (ms)": sum(aes_decrypt_times) / len(aes_decrypt_times) if aes_decrypt_times else 0,
                    "Key Match": all(key_matches)
                })

    for attr_count in attr_counts:
        for file_count in file_counts:
            for run in range(total_runs):
                ipfs = SimulatedIPFS()
                blockchain = SimulatedBlockchain()
                cpabe = CPABE(max_attributes=14, ipfs=ipfs, blockchain=blockchain)
                
                start_total_encrypt = time.perf_counter()
                
                PK, MK, setup_time = cpabe.setup(128)
                address_do = f"DO_Addr_run{run+1}_attrs{attr_count}_files{file_count}"
                address_du = f"DU_Addr_run{run+1}_attrs{attr_count}_files{file_count}"

                pro_enc_times = []
                encrypt_times = []
                aes_encrypt_times = []
                pro_dec_times = []
                decrypt_times = []
                aes_decrypt_times = []
                key_matches = []

                attrs = [f"attr{i+1}" for i in range(attr_count)]
                P = f"({' AND '.join(attrs)})"
                W = "keyword"

                for i in range(file_count):
                    fid = f"file_{attr_count}_run_{run+1}_file_{i+1}"

                    CT_1, pro_enc_time = cpabe.pro_enc(PK, P, attr_count)
                    pro_enc_times.append(pro_enc_time)
                    cpabe.reset_counters()

                    CT, Omega_i, I_w, ck, encrypt_time = cpabe.encrypt(PK, W, CT_1, P, fid, attr_count)
                    encrypt_times.append(encrypt_time)
                    cpabe.reset_counters()

                    message = os.urandom(1024)
                    encrypted_file, aes_enc_time = aes_encrypt(message, ck)
                    aes_encrypt_times.append(aes_enc_time)
                    HD = ipfs.store(fid, encrypted_file)
                    blockchain.storage(address_do, fid, CT, HD, I_w, Omega_i)

                total_encrypt_time = (time.perf_counter() - start_total_encrypt) * 1000

                start_total_decrypt = time.perf_counter()

                S = attrs
                SK, keygen_time = cpabe.key_gen(PK, MK, S, address_du)
                blockchain.set_usk(address_do, address_du, SK, 600)

                for i in range(file_count):
                    fid = f"file_{attr_count}_run_{run+1}_file_{i+1}"
                    token = cpabe.token(PK, SK, W, fid)
                    now_time = 30 + i * 1000
                    CT_retrieved, HD_retrieved, I_w_retrieved = blockchain.search(address_du, token, now_time, PK, P, W)

                    CT_2, CT_reencrypted, pro_dec_time = cpabe.pro_dec(SK, CT_retrieved, P, attr_count, address_du, fid, W=W, I_w=I_w_retrieved)
                    pro_dec_times.append(pro_dec_time)
                    cpabe.reset_counters()

                    ck_prime, decrypt_time = cpabe.decrypt(PK, CT_2, P, attr_count, CT_reencrypted)
                    decrypt_times.append(decrypt_time)
                    cpabe.reset_counters()

                    decrypted_file, aes_dec_time = aes_decrypt(ipfs.retrieve(HD_retrieved), ck_prime)
                    aes_decrypt_times.append(aes_dec_time)
                    key_matches.append(ck == ck_prime)

                total_decrypt_time = (time.perf_counter() - start_total_decrypt) * 1000

                fixed_attrs_results.append({
                    "Run": run + 1,
                    "File Count": file_count,
                    "Attributes": attr_count,
                    "Total Encrypt Time (ms)": total_encrypt_time,
                    "Avg ProEnc Time (ms)": sum(pro_enc_times) / len(pro_enc_times) if pro_enc_times else 0,
                    "Avg Encrypt Time (ms)": sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0,
                    "Avg AES Encrypt Time (ms)": sum(aes_encrypt_times) / len(aes_encrypt_times) if aes_encrypt_times else 0,
                    "Total Decrypt Time (ms)": total_decrypt_time,
                    "Avg ProDec Time (ms)": sum(pro_dec_times) / len(pro_dec_times) if pro_dec_times else 0,
                    "Avg Decrypt Time (ms)": sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0,
                    "Avg AES Decrypt Time (ms)": sum(aes_decrypt_times) / len(aes_decrypt_times) if aes_decrypt_times else 0,
                    "Key Match": all(key_matches)
                })

    averaged_fixed_files_results = []
    for file_count in file_counts:
        for attr_count in attr_counts:
            relevant_results = [r for r in fixed_files_results if r["File Count"] == file_count and r["Attributes"] == attr_count]
            if not relevant_results:
                continue
            avg_result = {
                "File Count": file_count,
                "Attributes": attr_count,
                "Total Encrypt Time (ms)": sum(r["Total Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg ProEnc Time (ms)": sum(r["Avg ProEnc Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg Encrypt Time (ms)": sum(r["Avg Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg AES Encrypt Time (ms)": sum(r["Avg AES Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Total Decrypt Time (ms)": sum(r["Total Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg ProDec Time (ms)": sum(r["Avg ProDec Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg Decrypt Time (ms)": sum(r["Avg Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg AES Decrypt Time (ms)": sum(r["Avg AES Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Key Match": all(r["Key Match"] for r in relevant_results)
            }
            averaged_fixed_files_results.append(avg_result)

    averaged_fixed_attrs_results = []
    for attr_count in attr_counts:
        for file_count in file_counts:
            relevant_results = [r for r in fixed_attrs_results if r["File Count"] == file_count and r["Attributes"] == attr_count]
            if not relevant_results:
                continue
            avg_result = {
                "File Count": file_count,
                "Attributes": attr_count,
                "Total Encrypt Time (ms)": sum(r["Total Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg ProEnc Time (ms)": sum(r["Avg ProEnc Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg Encrypt Time (ms)": sum(r["Avg Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg AES Encrypt Time (ms)": sum(r["Avg AES Encrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Total Decrypt Time (ms)": sum(r["Total Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg ProDec Time (ms)": sum(r["Avg ProDec Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg Decrypt Time (ms)": sum(r["Avg Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Avg AES Decrypt Time (ms)": sum(r["Avg AES Decrypt Time (ms)"] for r in relevant_results) / len(relevant_results),
                "Key Match": all(r["Key Match"] for r in relevant_results)
            }
            averaged_fixed_attrs_results.append(avg_result)

    with open("fixed_files_variable_attrs.csv", "w", newline="") as csvfile:
        fieldnames = [
            "File Count", "Attributes", "Total Encrypt Time (ms)", "Avg ProEnc Time (ms)",
            "Avg Encrypt Time (ms)", "Avg AES Encrypt Time (ms)", "Total Decrypt Time (ms)",
            "Avg ProDec Time (ms)", "Avg Decrypt Time (ms)", "Avg AES Decrypt Time (ms)", "Key Match"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in averaged_fixed_files_results:
            writer.writerow(row)

    with open("fixed_attrs_variable_files.csv", "w", newline="") as csvfile:
        fieldnames = [
            "File Count", "Attributes", "Total Encrypt Time (ms)", "Avg ProEnc Time (ms)",
            "Avg Encrypt Time (ms)", "Avg AES Encrypt Time (ms)", "Total Decrypt Time (ms)",
            "Avg ProDec Time (ms)", "Avg Decrypt Time (ms)", "Avg AES Decrypt Time (ms)", "Key Match"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in averaged_fixed_attrs_results:
            writer.writerow(row)

    return averaged_fixed_files_results, averaged_fixed_attrs_results

class TestCPABE(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.group = PairingGroup('SS512')
        self.max_attributes = 14
        self.results = []
        self.encryption_counts = [2, 4, 6, 8, 10, 12, 14]
        self.attribute_counts = [2, 4, 6, 8, 10, 12, 14]
        self.csv_data = []

    def measure_time(self, func, *args, desc: str, **kwargs):
        start_time = time.perf_counter()
        result = None
        success = False
        try:
            result = func(*args, **kwargs)
            success = result is not None
        except Exception as e:
            print(f"Error in {desc}: {str(e)}")
            return (None, None)
        elapsed = (time.perf_counter() - start_time) * 1000
        self.results.append({
            "operation": desc,
            "time": elapsed,
            "success": success,
            "file_count": len(self.ipfs.storage) if hasattr(self, 'ipfs') else 0
        })
        return result

    def tearDown(self):
        with open("detailed_benchmark_results.csv", "w", newline="") as csvfile:
            fieldnames = [
                "Scenario", "Files", "Attributes", "Policy", "Setup Time (ms)", "Keygen Time (ms)",
                "Encrypt Time (ms)", "Decrypt Time (ms)", "MPK Size (Bytes)", "MSK Size (Bytes)",
                "SK Size (Bytes)", "CT Size (Bytes)", "Success Rate (%)"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.csv_data:
                writer.writerow(row)

    def generate_access_policy(self, attr_count: int, file_count: int):
        attrs = [f"attr{i+1}" for i in range(attr_count)]
        single_policy = f"({' AND '.join(attrs)})" if attrs else "()"
        policies = [single_policy for _ in range(file_count)]
        return policies

    def generate_attributes(self, attr_count: int):
        return [f"attr{i+1}" for i in range(attr_count)]

    def judge_attrs(self, user_attrs: List[str], policy: str) -> bool:
        required_attrs = [attr.strip() for attr in policy.strip('()').split(' AND ')]
        return all(attr in user_attrs for attr in required_attrs)

    async def run_scenario(self, GID: str, num_encryptions: int, num_attributes: int, deposit: int, scenario: str):
        print(f"Running scenario: {scenario}, Files: {num_encryptions}, Attributes: {num_attributes}")
        self.ipfs = SimulatedIPFS()
        self.blockchain = SimulatedBlockchain()
        self.cpabe = CPABE(max_attributes=self.max_attributes, ipfs=self.ipfs, blockchain=self.blockchain)
        self.current_attr_count = num_attributes
        
        start_total_encrypt = time.perf_counter()
        PK, MK, setup_time = self.measure_time(self.cpabe.setup, 128, desc="Setup")
        address_do = f"DO_Addr_{GID}"
        message = os.urandom(1024)
        W = "keyword"
        policies = self.generate_access_policy(num_attributes, num_encryptions)
        user_attrs = self.generate_attributes(num_attributes)
        encryptions = []
        ct_sizes = []
        pro_enc_times = []
        encrypt_times = []
        aes_encrypt_times = []
        
        for i in range(num_encryptions):
            fid = f"{GID}_{i+1}"
            P = policies[i]
            CT_1 = self.measure_time(self.cpabe.pro_enc, PK, P, attr_count=num_attributes, desc=f"ProEnc_NFT{i+1}")
            pro_enc_times.append(CT_1[1] if CT_1[1] is not None else 0)
            CT, Omega_i, I_w, ck, encrypt_time = self.measure_time(
                self.cpabe.encrypt, PK, W, CT_1[0], P, fid, attr_count=num_attributes, file_count=num_encryptions,
                desc=f"Encrypt_NFT{i+1}"
            )
            encrypt_times.append(encrypt_time if encrypt_time is not None else 0)
            encrypted_file = self.measure_time(
                aes_encrypt, message, ck, desc=f"AESEncrypt_NFT{i+1}"
            )
            aes_encrypt_times.append(encrypted_file[1] if encrypted_file[1] is not None else 0)
            HD = self.measure_time(
                self.ipfs.store, fid, encrypted_file[0], desc=f"IPFSStore_NFT{i+1}"
            )
            success = self.measure_time(
                self.blockchain.storage, address_do, fid, CT, HD, I_w, Omega_i,
                desc=f"BlockchainStore_NFT{i+1}"
            )
            encryptions.append((message, CT, HD, ck, fid, P, I_w))
            ct_size = (sum(len(self.group.serialize(c)) for c in [CT['C'], CT['C_0'], CT['C_1'], CT['C2']]) +
                       sum(len(self.group.serialize(c)) for c in CT['C_y'].values()) +
                       len(CT['k_1_enc']) +
                       len(P.encode()))
            ct_sizes.append(ct_size)
        
        total_encrypt_time = (time.perf_counter() - start_total_encrypt) * 1000

        start_total_decrypt = time.perf_counter()
        address_du = f"DU_Addr_{GID}"
        SK = self.measure_time(self.cpabe.key_gen, PK, MK, user_attrs, address_du, desc="KeyGen")
        keygen_time = self.results[-1]["time"]
        self.measure_time(
            self.blockchain.set_usk, address_do, address_du, E_SK=SK[0], deadline=600,
            desc="SetUserKey"
        )
        decrypt_times = []
        aes_decrypt_times = []
        success_count = 0
        access_granted_count = 0
        now_time = 30
        combined_policy = policies[0] if policies else ""
        for i, (original_message, CT, HD, ck, fid, P, I_w) in enumerate(encryptions):
            access = self.judge_attrs(user_attrs, policies[i])
            if not access:
                print(f"Access denied for file {i+1}: Policy {P}, User attrs {user_attrs}")
                continue
            access_granted_count += 1
            try:
                token = self.cpabe.token(PK, SK[0], W, fid)
                search_result = self.measure_time(
                    self.blockchain.search, address_du, token, now_time, PK, P, W,
                    desc=f"Search_NFT{i+1}"
                )
                if search_result == (None, None):
                    print(f"Search failed for file {i+1}")
                    continue
                CT_retrieved, HD_retrieved, I_w_retrieved = search_result
                self.measure_time(self.blockchain.verify_audit_log, fid, desc=f"AuditLog_NFT{i+1}")
                SK_prime = SK[0]
                CT_2, CT_reencrypted, pro_dec_time = self.measure_time(
                    self.cpabe.pro_dec, SK_prime, CT_retrieved, P, num_attributes, address_du, fid,
                    measure_time_func=self.measure_time, W=W, I_w=I_w_retrieved,
                    desc=f"ProDec_NFT{i+1}"
                )
                ck_prime, decrypt_time = self.measure_time(
                    self.cpabe.decrypt, PK, CT_2, P, num_attributes, CT_reencrypted,
                    measure_time_func=self.measure_time, desc=f"Decrypt_NFT{i+1}"
                )
                decrypt_times.append(decrypt_time if decrypt_time is not None else 0)
                decrypted_file = self.measure_time(
                    aes_decrypt, self.ipfs.retrieve(HD_retrieved), ck_prime,
                    desc=f"AESDecrypt_NFT{i+1}"
                )
                aes_decrypt_times.append(decrypted_file[1] if decrypted_file[1] is not None else 0)
                success = decrypted_file[0] == original_message and deposit >= 1000
                print(f"File {i+1} decryption successful: {success}")
                if success:
                    success_count += 1
            except Exception as e:
                print(f"Decryption failed for file {i+1}: {str(e)}")
                continue
            now_time += 1000
        
        total_decrypt_time = (time.perf_counter() - start_total_decrypt) * 1000
        
        mpk_size = (len(self.group.serialize(PK['g'])) +
                    len(self.group.serialize(PK['g_alpha'])) +
                    len(self.group.serialize(PK['g_beta'])) +
                    len(self.group.serialize(PK['e_g_g_alpha'])) +
                    sum(len(self.group.serialize(v)) for v in PK['AK'].values()))
        msk_size = (len(self.group.serialize(MK['alpha'])) +
                    len(self.group.serialize(MK['beta'])) +
                    sum(len(self.group.serialize(v)) for v in MK['v'].values()))
        sk_size = (len(self.group.serialize(SK[0]['S_1'])) +
                   len(self.group.serialize(SK[0]['S_2'])) +
                   sum(len(self.group.serialize(v)) for v in SK[0]['S_i'].values()))
        success_rate = (success_count / num_encryptions * 100) if num_encryptions > 0 else 0
        self.csv_data.append({
            "Scenario": scenario,
            "Files": num_encryptions,
            "Attributes": num_attributes,
            "Policy": combined_policy,
            "Setup Time (ms)": setup_time,
            "Keygen Time (ms)": keygen_time,
            "Encrypt Time (ms)": total_encrypt_time,
            "Decrypt Time (ms)": total_decrypt_time,
            "MPK Size (Bytes)": mpk_size,
            "MSK Size (Bytes)": msk_size,
            "SK Size (Bytes)": sk_size,
            "CT Size (Bytes)": sum(ct_sizes) / len(ct_sizes) if ct_sizes else 0,
            "Success Rate (%)": success_rate
        })
        print(f"Scenario {scenario} completed: {success_count}/{num_encryptions} successes")
        return {"success_count": success_count, "total": num_encryptions, "access_granted_count": access_granted_count}

    async def test_all_combinations(self):
        for fixed_file_count in self.encryption_counts:
            for attr_count in self.attribute_counts:
                with self.subTest(fixed_file_count=fixed_file_count, attr_count=attr_count):
                    GID = f"NFT_fixed_files{fixed_file_count}_attr{attr_count}"
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=fixed_file_count,
                        num_attributes=attr_count,
                        deposit=1500,
                        scenario=f"Fixed_Files_{fixed_file_count}_Attrs_{attr_count}"
                    )
                    self.assertEqual(
                        result["success_count"], fixed_file_count,
                        f"Scenario {GID}: Expected {fixed_file_count} successes, got {result['success_count']}"
                    )
        
        for fixed_attr_count in self.attribute_counts:
            for enc_count in self.encryption_counts:
                with self.subTest(enc_count=enc_count, fixed_attr_count=fixed_attr_count):
                    GID = f"NFT_enc{enc_count}_fixed_attr{fixed_attr_count}"
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=enc_count,
                        num_attributes=fixed_attr_count,
                        deposit=1500,
                        scenario=f"Fixed_Attrs_{fixed_attr_count}_Files_{enc_count}"
                    )
                    self.assertEqual(
                        result["success_count"], enc_count,
                        f"Scenario {GID}: Expected {enc_count} successes, got {result['success_count']}"
                    )

def main():
    try:
        total_runs = 5
        fixed_files_results, fixed_attrs_results = measure_policy_hiding_overhead(total_runs)
        
        print("\nResults for Fixed Files, Variable Attributes:")
        for result in fixed_files_results:
            print(f"File Count: {result['File Count']}, Attributes: {result['Attributes']}")
            print(f"  Total Encrypt Time (Avg): {result['Total Encrypt Time (ms)']:.2f} ms")
            print(f"  Avg ProEnc Time: {result['Avg ProEnc Time (ms)']:.2f} ms")
            print(f"  Avg Encrypt Time: {result['Avg Encrypt Time (ms)']:.2f} ms")
            print(f"  Avg AES Encrypt Time: {result['Avg AES Encrypt Time (ms)']:.2f} ms")
            print(f"  Total Decrypt Time (Avg): {result['Total Decrypt Time (ms)']:.2f} ms")
            print(f"  Avg ProDec Time: {result['Avg ProDec Time (ms)']:.2f} ms")
            print(f"  Avg Decrypt Time: {result['Avg Decrypt Time (ms)']:.2f} ms")
            print(f"  Avg AES Decrypt Time: {result['Avg AES Decrypt Time (ms)']:.2f} ms")
            print(f"  Key Match: {result['Key Match']}")

        print("\nResults for Fixed Attributes, Variable Files:")
        for result in fixed_attrs_results:
            print(f"File Count: {result['File Count']}, Attributes: {result['Attributes']}")
            print(f"  Total Encrypt Time (Avg): {result['Total Encrypt Time (ms)']:.2f} ms")
            print(f"  Avg ProEnc Time: {result['Avg ProEnc Time (ms)']:.2f} ms")
            print(f"  Avg Encrypt Time: {result['Avg Encrypt Time (ms)']:.2f} ms")
            print(f"  Avg AES Encrypt Time: {result['Avg AES Encrypt Time (ms)']:.2f} ms")
            print(f"  Total Decrypt Time (Avg): {result['Total Decrypt Time (ms)']:.2f} ms")
            print(f"  Avg ProDec Time: {result['Avg ProDec Time (ms)']:.2f} ms")
            print(f"  Avg Decrypt Time: {result['Avg Decrypt Time (ms)']:.2f} ms")
            print(f"  Avg AES Decrypt Time: {result['Avg AES Decrypt Time (ms)']:.2f} ms")
            print(f"  Key Match: {result['Key Match']}")

    except Exception as e:
        print(f"Main error: {str(e)}")

if __name__ == "__main__":
    unittest.main()