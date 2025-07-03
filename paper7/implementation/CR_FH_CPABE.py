import time
import csv
import logging
from typing import List, Dict, Set, Optional, Tuple, Any
from Crypto.Random import get_random_bytes
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from functools import reduce
try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AccessTreeNode:
    """Represents a node in the hierarchical access tree."""
    def __init__(self, type_: str, gate_type: Optional[str] = None, attribute: Optional[str] = None, 
                 threshold: Optional[int] = None, level_node_id: Optional[str] = None):
        self.type = type_
        self.gate_type = gate_type
        self.attribute = attribute
        self.threshold = threshold
        self.children: List['AccessTreeNode'] = []
        self.index: Optional[int] = None
        self.parent: Optional['AccessTreeNode'] = None
        self.level_node_id = level_node_id
        self.q_x_0 = None

    def add_child(self, child: 'AccessTreeNode') -> None:
        child.index = len(self.children)
        child.parent = self
        self.children.append(child)

    def __str__(self, indent: int = 0) -> str:
        result = "  " * indent
        if self.type == "leaf":
            result += f"Leaf({self.attribute})"
        else:
            result += f"Gate({self.gate_type}, threshold={self.threshold}"
            if self.level_node_id:
                result += f", id={self.level_node_id}"
            result += ")"
        result += '\n'
        for child in self.children:
            result += child.__str__(indent + 1)
        return result

def create_access_tree(num_attributes: int, attributes: List[str] = None, level_node_id: str = None) -> AccessTreeNode:
    if attributes is None or len(attributes) != num_attributes:
        attributes = [f"attr{i+1}" for i in range(num_attributes)]
    if len(attributes) != num_attributes:
        raise ValueError(f"Expected exactly {num_attributes} attributes, got {len(attributes)}")
    
    root = AccessTreeNode("gate", gate_type="AND", threshold=num_attributes, level_node_id=level_node_id)
    for attr in attributes:
        leaf = AccessTreeNode("leaf", attribute=attr)
        root.add_child(leaf)
    return root

def get_leaves(node: AccessTreeNode) -> List[AccessTreeNode]:
    leaves = []
    if node.type == "leaf":
        leaves.append(node)
    else:
        for child in node.children:
            leaves.extend(get_leaves(child))
    return leaves

def chunk_data(data: bytes, chunk_size: int) -> List[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

class CRFHCPABE:
    """Collusion-Resistant File-Hierarchy CP-ABE scheme."""
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.G1 = self.group.random(G1)
        self.order = self.group.order()
        self._cached_pairs = {}
        self._cached_h1 = {}
        self._cached_h3 = {}
        self._serialized_cache = {}
        self.chunk_size = 128
        self._precomputed_egg = pair(self.G1, self.G1)
        self.pairing_count = 0 

    def reset_counters(self):
        self.pairing_count = 0

    def H1(self, input_str: str) -> G1:
        if input_str not in self._cached_h1:
            hash_val = hashlib.sha256(input_str.encode()).digest()
            self._cached_h1[input_str] = self.G1 ** self.group.hash(hash_val, ZR)
        return self._cached_h1[input_str]

    def H3(self, input_str: str) -> ZR:
        if input_str not in self._cached_h3:
            hash_val = hashlib.sha256(input_str.encode()).digest()
            self._cached_h3[input_str] = self.group.hash(hash_val, ZR)
        return self._cached_h3[input_str]

    def setup(self) -> Tuple[Dict, Dict]:
        g = self.G1
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        beta_inv = ~beta
        f = g ** beta
        e_gg_alpha = self._precomputed_egg ** alpha
        MPK = {'g': g, 'f': f, 'e_gg_alpha': e_gg_alpha, 'beta_inv': beta_inv}
        MSK = {'alpha': alpha, 'beta': beta}
        return MPK, MSK

    def keygen(self, MPK: Dict, MSK: Dict, attributes: Set[str], uid: str) -> Dict:
        SK = {}
        r_i = self.group.random(ZR)
        omega1 = self.H3(uid)
        SK['D_i'] = MPK['g'] ** ((MSK['alpha'] + omega1) * MPK['beta_inv'])
        SK['D_omega'] = MPK['g'] ** omega1
        g = MPK['g']
        h1_attrs = {attr: self.H1(attr) for attr in attributes}
        for attr in attributes:
            r_i_j = self.group.random(ZR)
            SK[f'D_{attr}'] = (g ** (r_i + omega1)) * (h1_attrs[attr] ** r_i_j)
            SK[f'D_prime_{attr}'] = g ** r_i_j
        return SK

    def encrypt(self, MPK: Dict, data: bytes, access_tree: AccessTreeNode) -> Dict:
        CT = {}
        chunks = chunk_data(data, self.chunk_size)
        encrypted_chunks = []
        attributes = [leaf.attribute for leaf in get_leaves(access_tree)]
        access_trees = [create_access_tree(len(attributes), attributes, f"L{i+1}") for i in range(len(chunks))]
        
        for i, chunk in enumerate(chunks):

                
            
            s = self.group.random(ZR)
            aes_key_gt = self._precomputed_egg ** s
            aes_key = hashlib.sha256(self.group.serialize(aes_key_gt)).digest()[:16]
            
            iv = get_random_bytes(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher.encrypt(pad(chunk, AES.block_size))
            encrypted_chunks.append((iv, ciphertext))
            
            node_id = access_trees[i].level_node_id
            CT[f'C_{node_id}'] = aes_key_gt * (MPK['e_gg_alpha'] ** s)
            CT[f'C_prime_{node_id}'] = MPK['f'] ** s
            CT[f'C_double_prime_{node_id}'] = MPK['g'] ** s
            for attr in attributes:
                CT[f'C_{attr}_{node_id}'] = self.H1(attr) ** s
        
        CT['encrypted_chunks'] = encrypted_chunks
        CT['access_trees'] = access_trees
        return CT

    def evaluate_node(self, node: AccessTreeNode, CT: Dict, SK: Dict, user_attributes: Set[str], node_id: str, pairing_cache: Dict) -> Optional[Any]:
        if node.type == "leaf":
            attr = node.attribute
            if attr not in user_attributes:
                return None
            C_attr = CT.get(f'C_{attr}_{node_id}')
            D_attr = SK.get(f'D_{attr}')
            D_prime_attr = SK.get(f'D_prime_{attr}')
            C_double_prime = CT.get(f'C_double_prime_{node_id}')
            if not all([C_attr, D_attr, D_prime_attr, C_double_prime]):
                return None
            
            cache_key1 = (id(C_attr), id(D_prime_attr))
            cache_key2 = (id(D_attr), id(C_double_prime))
            
            if cache_key1 not in pairing_cache:
                pairing_cache[cache_key1] = pair(C_attr, D_prime_attr)
            if cache_key2 not in pairing_cache:
                pairing_cache[cache_key2] = pair(D_attr, C_double_prime)
            
            return pairing_cache[cache_key1] / pairing_cache[cache_key2]
        else:
            results = [self.evaluate_node(child, CT, SK, user_attributes, node_id, pairing_cache) 
                      for child in node.children if self.evaluate_node(child, CT, SK, user_attributes, node_id, pairing_cache)]
            if node.gate_type == "AND" and len(results) == len(node.children) and len(results) >= node.threshold:
                return reduce(lambda x, y: x * y, results, 1) if results else None
            return None

    def decrypt(self, MPK: Dict, CT: Dict, SK: Dict, user_attributes: Set[str]) -> bytes:
        pairing_cache = {}
        encrypted_chunks = CT['encrypted_chunks']
        level_nodes = CT['access_trees']
        decrypted_chunks = []


        D_omega = SK['D_omega']
        D_i = SK['D_i']
        
        for i, node in enumerate(level_nodes):
            result = self.evaluate_node(node, CT, SK, user_attributes, node.level_node_id, pairing_cache)
            if result is None:
                logging.info(f"Chunk {i+1}/{len(encrypted_chunks)}: Access policy not satisfied")
                return b""
            
            C_prime = CT[f'C_prime_{node.level_node_id}']
            C_double_prime = CT[f'C_double_prime_{node.level_node_id}']
            cache_key_f_x = (id(C_double_prime), id(D_omega))
            cache_key_term = (id(C_prime), id(D_i))
            
            if cache_key_f_x not in pairing_cache:
                pairing_cache[cache_key_f_x] = pair(C_double_prime, D_omega)
            if cache_key_term not in pairing_cache:
                pairing_cache[cache_key_term] = pair(C_prime, D_i)
            
            F_x = pairing_cache[cache_key_f_x]
            term = pairing_cache[cache_key_term] / F_x
            aes_key_gt = CT[f'C_{node.level_node_id}'] / term
            aes_key = hashlib.sha256(self.group.serialize(aes_key_gt)).digest()[:16]
            
            try:
                iv, ct = encrypted_chunks[i]
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
                decrypted_chunk = unpad(cipher.decrypt(ct), AES.block_size)
                decrypted_chunks.append(decrypted_chunk)
                logging.info(f"Chunk {i+1}/{len(encrypted_chunks)}: Decryption successful")
            except Exception:
                logging.info(f"Chunk {i+1}/{len(encrypted_chunks)}: Decryption failed")
                return b""
        
        return b"".join(decrypted_chunks)

    def compute_sizes(self, MPK: Dict, MSK: Dict, SK: Dict, CT: Dict) -> Dict[str, int]:
        sizes = {}
        for key, value in MPK.items():
            if key not in self._serialized_cache:
                self._serialized_cache[key] = self.group.serialize(value)
            sizes['MPK'] = sizes.get('MPK', 0) + len(self._serialized_cache[key])
        for key, value in MSK.items():
            if key not in self._serialized_cache:
                self._serialized_cache[key] = self.group.serialize(value)
            sizes['MSK'] = sizes.get('MSK', 0) + len(self._serialized_cache[key])
        for key, value in SK.items():
            if key not in self._serialized_cache:
                self._serialized_cache[key] = self.group.serialize(value)
            sizes['SK'] = sizes.get('SK', 0) + len(self._serialized_cache[key])
        ct_bytes = 0
        for key, value in CT.items():
            if key == 'encrypted_chunks':
                for iv, ct in value:
                    ct_bytes += len(iv) + len(ct)
            elif key == 'access_trees':
                for tree in value:
                    ct_bytes += (1 + len(get_leaves(tree))) * 100
            else:
                if key not in self._serialized_cache:
                    self._serialized_cache[key] = self.group.serialize(value)
                ct_bytes += len(self._serialized_cache[key])
        sizes['CT'] = ct_bytes
        return sizes

def policy_to_string(node: AccessTreeNode, indent: int = 0) -> str:
    if node.type == "leaf":
        return node.attribute
    children_str = [policy_to_string(child, indent + 1) for child in node.children]
    gate_str = f"{' AND '.join(children_str)}"
    if len(children_str) > 1:
        gate_str = f"({gate_str})"
    if node.level_node_id:
        gate_str = f"{node.level_node_id}: {gate_str}"
    return gate_str

def run_benchmark():
    cpabe = CRFHCPABE()
    logging.info("Starting benchmark for CR-FH-CPABE...")
    file_counts = [2, 4, 6, 8, 10, 12, 14]
    attr_counts = [2, 4, 6, 8, 10, 12, 14]
    chunk_size = 256
    chunks_per_file = 2
    num_runs = 1
    results = []

    # Scenario 1: Fixed files, varying attributes
    logging.info("Running Scenario 1: Fixed files, varying attributes")
    for n_files in file_counts:
        total_chunks = n_files * chunks_per_file
        for n_attrs in attr_counts:
            attributes = [f"attr{i+1}" for i in range(n_attrs)]
            user_attrs = set(attributes)
            access_tree = create_access_tree(n_attrs, attributes, "L1")
            policy_str = " OR ".join([f"L{i+1}: ({' AND '.join(attributes)})" for i in range(total_chunks)])
            scenario = f"Fixed_Files_{n_files}_Attrs_{n_attrs}"

            setup_time = keygen_time = encrypt_time = decrypt_time = 0
            success_count = 0
            sizes = {'MPK': 0, 'MSK': 0, 'SK': 0, 'CT': 0}
            pairing_count = 0

            for run in range(num_runs):
                data_list = [get_random_bytes(1024) for _ in range(n_files)]
                ciphertext_list = []

                start_time = time.time()
                try:
                    MPK, MSK = cpabe.setup()
                except Exception:
                    continue
                setup_time += time.time() - start_time

                start_time = time.time()
                try:
                    SK = cpabe.keygen(MPK, MSK, user_attrs, f"user_{run+1}")
                except Exception:
                    continue
                keygen_time += time.time() - start_time

                start_time = time.time()
                for i, data in enumerate(data_list):
                    cpabe.reset_counters()
                    try:
                        CT = cpabe.encrypt(MPK, data, access_tree)
                        ciphertext_list.append(CT)
                        pairing_count += cpabe.pairing_count
                    except Exception:
                        continue
                encrypt_time += time.time() - start_time

                start_time = time.time()
                decrypted_data_all = []
                for i, CT in enumerate(ciphertext_list):
                    cpabe.reset_counters()
                    try:
                        decrypted_data = cpabe.decrypt(MPK, CT, SK, user_attrs)
                        decrypted_data_all.append(decrypted_data)
                        pairing_count += cpabe.pairing_count
                        if decrypted_data != data_list[i]:
                            decrypted_data_all[-1] = b""
                    except Exception:
                        decrypted_data_all.append(b"")
                decrypt_time += time.time() - start_time
                logging.info(f"Run {run+1}, Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}: Decryption time = {decrypt_time:.6f}s")

                for CT in ciphertext_list:
                    run_sizes = cpabe.compute_sizes(MPK, MSK, SK, CT)
                    for key in sizes:
                        sizes[key] += run_sizes[key]
                for key in sizes:
                    sizes[key] = sizes[key] // len(ciphertext_list) if ciphertext_list else 0

                if ciphertext_list and all(decrypted_data == data_list[i] for i, decrypted_data in enumerate(decrypted_data_all)):
                    success_count += 1
                else:
                    logging.info(f"Run {run+1}, Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}: Decryption failed for one or more files")

            avg_setup = (setup_time / num_runs) * 1000
            avg_keygen = (keygen_time / num_runs) * 1000
            avg_encrypt = (encrypt_time / num_runs) * 1000
            avg_decrypt = (decrypt_time / num_runs) * 1000
            success_rate = (success_count / num_runs) * 100
            for key in sizes:
                sizes[key] = sizes[key] // num_runs if success_count > 0 else 0

            logging.info(f"Scenario 1: Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}, Success Rate={success_rate:.2f}%")

            results.append({
                'Scenario': scenario,
                'Files': n_files,
                'Chunks': total_chunks,
                'Attributes': n_attrs,
                'Policy': policy_str,
                'Setup Time (ms)': avg_setup,
                'Keygen Time (ms)': avg_keygen,
                'Encrypt Time (ms)': avg_encrypt,
                'Decrypt Time (ms)': avg_decrypt,
                'MPK Size (Bytes)': sizes['MPK'],
                'MSK Size (Bytes)': sizes['MSK'],
                'SK Size (Bytes)': sizes['SK'],
                'CT Size (Bytes)': sizes['CT'],
                'Success Rate (%)': success_rate
            })

    # Scenario 2: Fixed attributes, varying files
    logging.info("Running Scenario 2: Fixed attributes, varying files")
    for n_attrs in attr_counts:
        attributes = [f"attr{i+1}" for i in range(n_attrs)]
        user_attrs = set(attributes)
        for n_files in file_counts:
            total_chunks = n_files * chunks_per_file
            access_tree = create_access_tree(n_attrs, attributes, "L1")
            policy_str = " OR ".join([f"L{i+1}: ({' AND '.join(attributes)})" for i in range(total_chunks)])
            scenario = f"Fixed_Attrs_{n_attrs}_Files_{n_files}"

            setup_time = keygen_time = encrypt_time = decrypt_time = 0
            success_count = 0
            sizes = {'MPK': 0, 'MSK': 0, 'SK': 0, 'CT': 0}
            pairing_count = 0

            for run in range(num_runs):
                data_list = [get_random_bytes(1024) for _ in range(n_files)]
                ciphertext_list = []

                start_time = time.time()
                try:
                    MPK, MSK = cpabe.setup()
                except Exception:
                    continue
                setup_time += time.time() - start_time

                start_time = time.time()
                try:
                    SK = cpabe.keygen(MPK, MSK, user_attrs, f"user_{run+1}")
                except Exception:
                    continue
                keygen_time += time.time() - start_time

                start_time = time.time()
                for i, data in enumerate(data_list):
                    cpabe.reset_counters()
                    try:
                        CT = cpabe.encrypt(MPK, data, access_tree)
                        ciphertext_list.append(CT)
                        pairing_count += cpabe.pairing_count
                    except Exception:
                        continue
                encrypt_time += time.time() - start_time

                start_time = time.time()
                decrypted_data_all = []
                for i, CT in enumerate(ciphertext_list):
                    cpabe.reset_counters()
                    try:
                        decrypted_data = cpabe.decrypt(MPK, CT, SK, user_attrs)
                        decrypted_data_all.append(decrypted_data)
                        pairing_count += cpabe.pairing_count
                        if decrypted_data != data_list[i]:
                            decrypted_data_all[-1] = b""
                    except Exception:
                        decrypted_data_all.append(b"")
                decrypt_time += time.time() - start_time
                logging.info(f"Run {run+1}, Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}: Decryption time = {decrypt_time:.6f}s")

                for CT in ciphertext_list:
                    run_sizes = cpabe.compute_sizes(MPK, MSK, SK, CT)
                    for key in sizes:
                        sizes[key] += run_sizes[key]
                for key in sizes:
                    sizes[key] = sizes[key] // len(ciphertext_list) if ciphertext_list else 0

                if ciphertext_list and all(decrypted_data == data_list[i] for i, decrypted_data in enumerate(decrypted_data_all)):
                    success_count += 1
                else:
                    logging.info(f"Run {run+1}, Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}: Decryption failed for one or more files")

            avg_setup = (setup_time / num_runs) * 1000
            avg_keygen = (keygen_time / num_runs) * 1000
            avg_encrypt = (encrypt_time / num_runs) * 1000
            avg_decrypt = (decrypt_time / num_runs) * 1000
            success_rate = (success_count / num_runs) * 100
            for key in sizes:
                sizes[key] = sizes[key] // num_runs if success_count > 0 else 0

            logging.info(f"Scenario 2: Files={n_files}, Chunks={total_chunks}, Attrs={n_attrs}, Success Rate={success_rate:.2f}%")

            results.append({
                'Scenario': scenario,
                'Files': n_files,
                'Chunks': total_chunks,
                'Attributes': n_attrs,
                'Policy': policy_str,
                'Setup Time (ms)': avg_setup,
                'Keygen Time (ms)': avg_keygen,
                'Encrypt Time (ms)': avg_encrypt,
                'Decrypt Time (ms)': avg_decrypt,
                'MPK Size (Bytes)': sizes['MPK'],
                'MSK Size (Bytes)': sizes['MSK'],
                'SK Size (Bytes)': sizes['SK'],
                'CT Size (Bytes)': sizes['CT'],
                'Success Rate (%)': success_rate
            })

    csv_headers = ['Scenario', 'Files', 'Chunks', 'Attributes', 'Policy', 'Setup Time (ms)', 'Keygen Time (ms)', 
                   'Encrypt Time (ms)', 'Decrypt Time (ms)', 'MPK Size (Bytes)', 
                   'MSK Size (Bytes)', 'SK Size (Bytes)', 'CT Size (Bytes)', 
                   'Success Rate (%)']
    with open('detailed_benchmark_results.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    logging.info("Results saved to detailed_benchmark_results.csv")

    if tabulate:
        print_performance_tables(file_counts, attr_counts, results)
    else:
        print("\nScenario 1: Fixed Files, Varying Attributes:")
        for n_files in file_counts:
            for n_attrs in attr_counts:
                try:
                    result = next(r for r in results if r['Scenario'] == f"Fixed_Files_{n_files}_Attrs_{n_attrs}")
                    print(f"Files={n_files}, Chunks={result['Chunks']}, Attrs={result['Attributes']}, "
                          f"Encrypt={result['Encrypt Time (ms)']:.6f}ms, Decrypt={result['Decrypt Time (ms)']:.6f}ms, "
                          f"Success={result['Success Rate (%)']:.1f}%")
                except StopIteration:
                    pass
        print("\nScenario 2: Fixed Attributes, Varying Files:")
        for n_attrs in attr_counts:
            for n_files in file_counts:
                try:
                    result = next(r for r in results if r['Scenario'] == f"Fixed_Attrs_{n_attrs}_Files_{n_files}")
                    print(f"Files={n_files}, Chunks={result['Chunks']}, Attrs={result['Attributes']}, "
                          f"Encrypt={result['Encrypt Time (ms)']:.6f}ms, Decrypt={result['Decrypt Time (ms)']:.6f}ms, "
                          f"Success={result['Success Rate (%)']:.1f}%")
                except StopIteration:
                    pass

def print_performance_tables(file_counts: List[int], attr_counts: List[int], results: List[Dict]) -> None:
    if not tabulate:
        return
    print("\nScenario 1: Fixed Files, Varying Attributes:")
    table = [['Files', 'Chunks', 'Attributes', 'Policy', 'Setup (ms)', 'Keygen (ms)', 'Encrypt (ms)', 
              'Decrypt (ms)', 'MPK (B)', 'MSK (B)', 'SK (B)', 'CT (B)', 'Success (%)']]
    for n_files in file_counts:
        for n_attrs in attr_counts:
            try:
                result = next(r for r in results if r['Scenario'] == f"Fixed_Files_{n_files}_Attrs_{n_attrs}")
                table.append([
                    result['Files'], result['Chunks'], result['Attributes'], result['Policy'],
                    round(result['Setup Time (ms)'], 6), round(result['Keygen Time (ms)'], 6),
                    round(result['Encrypt Time (ms)'], 6), round(result['Decrypt Time (ms)'], 6),
                    result['MPK Size (Bytes)'], result['MSK Size (Bytes)'],
                    result['SK Size (Bytes)'], result['CT Size (Bytes)'],
                    round(result['Success Rate (%)'], 1)
                ])
            except StopIteration:
                continue
    print(tabulate(table, headers='firstrow', tablefmt='grid'))

    print("\nScenario 2: Fixed Attributes, Varying Files:")
    table = [['Files', 'Chunks', 'Attributes', 'Policy', 'Setup (ms)', 'Keygen (ms)', 'Encrypt (ms)', 
              'Decrypt (ms)', 'MPK (B)', 'MSK (B)', 'SK (B)', 'CT (B)', 'Success (%)']]
    for n_attrs in attr_counts:
        for n_files in file_counts:
            try:
                result = next(r for r in results if r['Scenario'] == f"Fixed_Attrs_{n_attrs}_Files_{n_files}")
                table.append([
                    result['Files'], result['Chunks'], result['Attributes'], result['Policy'],
                    round(result['Setup Time (ms)'], 6), round(result['Keygen Time (ms)'], 6),
                    round(result['Encrypt Time (ms)'], 6), round(result['Decrypt Time (ms)'], 6),
                    result['MPK Size (Bytes)'], result['MSK Size (Bytes)'],
                    result['SK Size (Bytes)'], result['CT Size (Bytes)'],
                    round(result['Success Rate (%)'], 1)
                ])
            except StopIteration:
                continue
    print(tabulate(table, headers='firstrow', tablefmt='grid'))

def main():
    #----- TEST ENC/DEC CP_ABE -----
    cpabe = CRFHCPABE()
    MPK, MSK = cpabe.setup()
    num_attrs = 6
    attributes = [f"attr{i+1}" for i in range(num_attrs)]
    access_tree = create_access_tree(num_attrs, attributes, "L1")
    
    data = get_random_bytes(1024)
    try:
        ciphertext = cpabe.encrypt(MPK, data, access_tree)
    except ValueError as e:
        print(f"Encryption failed: {e}")
        return
    user_attributes = set(attributes)
    uid = "user1"
    private_key = cpabe.keygen(MPK, MSK, user_attributes, uid)
    decrypted_data = cpabe.decrypt(MPK, ciphertext, private_key, user_attributes)
    
    print("Decryption successful:", decrypted_data == data)

    #---------------------------

if __name__ == "__main__":
    run_benchmark()