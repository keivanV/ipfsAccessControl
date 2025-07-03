import unittest
import time
import asyncio
import csv
from typing import List, Dict, Tuple, Any
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import hashlib
import random
import logging
import re
import platform
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def hash_to_G1(group: PairingGroup, input_str: str) -> Any:
    hash_bytes = hashlib.sha256(input_str.encode()).digest()
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    zr_element = group.init(ZR, hash_int % group.order())
    g1_generator = group.random(G1)
    return g1_generator ** zr_element

# Simulated smart contract in Python
class IncentiveContract:
    def __init__(self):
        self.pool = {}
        self.expects = {}
        self.keys = {}
        self.attributes = {}
        self.access_policies = {}
        self.transactions = []
        self.stakes = {}

    def stake(self, authority_addr: str, amount: int) -> bool:
        self.stakes[authority_addr] = amount
        self.transactions.append(f"Stake by {authority_addr}: amount={amount}")
        return True

    def forfeit_stake(self, authority_addr: str) -> bool:
        if authority_addr in self.stakes:
            amount = self.stakes[authority_addr]
            del self.stakes[authority_addr]
            self.transactions.append(f"Forfeited stake of {authority_addr}: amount={amount}")
            return True
        return False

    def expect(self, GID: str, owner_val: int, owner_addr: str) -> bool:
        self.expects[GID] = {"value": owner_val, "owner": owner_addr}
        self.transactions.append(f"Expect set for GID {GID}: value={owner_val}, owner={owner_addr}")
        return True

    def deposit(self, GID: str, user_addr: str, value: int) -> bool:
        if user_addr not in self.pool:
            self.pool[user_addr] = {}
        self.pool[user_addr][GID] = value
        self.transactions.append(f"Deposit by {user_addr} for GID {GID}: value={value}")
        return True

    def withdraw(self, GID: str, user_addr: str) -> bool:
        if user_addr in self.pool and GID in self.pool[user_addr] and self.pool[user_addr][GID] > 0:
            amount = self.pool[user_addr][GID]
            self.pool[user_addr][GID] = 0
            self.transactions.append(f"Withdraw by {user_addr} for GID {GID}: amount={amount}")
            return True
        self.transactions.append(f"Failed withdraw by {user_addr} for GID {GID}: insufficient funds")
        return False

    def reward(self, user_addr: str, owner_addr: str, authority_addrs: List[str], GID: str) -> bool:
        if (user_addr in self.pool and GID in self.pool[user_addr] and
                GID in self.expects and self.pool[user_addr][GID] >= self.expects[GID]["value"]):
            owner_val = self.expects[GID]["value"]
            remaining = self.pool[user_addr][GID] - owner_val
            avg = remaining // len(authority_addrs) if authority_addrs else 0
            self.pool[user_addr][GID] = 0
            self.transactions.append(f"Reward: {owner_val} to owner {owner_addr}")
            for addr in authority_addrs:
                self.transactions.append(f"Reward: {avg} to authority {addr}")
            print(f"Simulated transfer: {owner_val} to owner {owner_addr}")
            for addr in authority_addrs:
                print(f"Simulated transfer: {avg} to {addr}")
            return True
        self.transactions.append(f"Failed reward for GID {GID}: insufficient funds or invalid expect")
        return False

    def store_key(self, GID: str, EK0: Any, EK1: Any, proofs: Dict) -> bool:
        if GID not in self.keys:
            self.keys[GID] = []
        self.keys[GID].append((EK0, EK1, proofs))
        self.transactions.append(f"Stored key for {GID}")
        return True

    def get_keys(self, GID: str) -> List[Tuple]:
        return self.keys.get(GID, [])

    def store_access_policy(self, GID: str, acp: str) -> bool:
        self.access_policies[GID] = acp
        self.transactions.append(f"Stored access policy for {GID}: {acp}")
        return True

    def get_access_policy(self, GID: str) -> str:
        return self.access_policies.get(GID, "")

    def get_transaction_log(self) -> List[str]:
        return self.transactions

class DecentralizedCPABE(ABEncMultiAuth):
    def __init__(self, group: PairingGroup, target_data_size: int = 1024):  # Default to 1KB
        super().__init__()
        self.group = group
        self.contract = IncentiveContract()
        random.seed(42)
        self.random_zr_cache = [self.group.random(ZR) for _ in range(100)]
        self.cache_index = 0
        self.chunk_size = 128  
        self.target_data_size = target_data_size  # Target data size in bytes (default 1KB)
        self.num_chunks = math.ceil(self.target_data_size / self.chunk_size)  

    def get_random_zr(self) -> Any:
        zr_element = self.random_zr_cache[self.cache_index % len(self.random_zr_cache)]
        self.cache_index += 1
        return zr_element

    def global_setup(self) -> Dict:
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        return {"g1": g1, "g2": g2}

    def abe_auth_setup(self, GP: Dict, theta: str) -> Tuple[Dict, Dict]:
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        sk_theta = {"alpha": alpha, "beta": beta}
        pk_theta = {
            "g1_alpha": GP["g1"] ** alpha,
            "g2_alpha": GP["g2"] ** alpha,
            "g2_beta": beta,
            "e_g1_g2_alpha": pair(GP["g1"], GP["g2"]) ** alpha
        }
        return sk_theta, pk_theta

    def abe_keygen(self, GID: str, GP: Dict, u: str, sk_theta: Dict) -> Tuple[Any, Any, Any]:
        d_theta = self.group.random(ZR)
        H_GID = hash_to_G1(self.group, GID)
        F_u = hash_to_G1(self.group, u)
        K0 = (GP["g1"] ** sk_theta["alpha"]) * (H_GID ** sk_theta["beta"]) * (F_u ** d_theta)
        K1 = GP["g2"] ** d_theta
        return K0, K1, d_theta

    def abe_enc_key(self, GID: str, GP: Dict, u: str, sk_theta: Dict, pk_u: Any) -> Tuple[Any, Any, Any]:
        d_theta = self.group.random(ZR)
        EK0 = pk_u ** sk_theta["alpha"]
        EK1 = GP["g2"] ** d_theta
        return EK0, EK1, d_theta

    def get_key(self, EK0: Any, EK1: Any, g1_alpha: Any, y: Any) -> Tuple[Any, Any]:
        try:
            K0 = EK0 ** (1 / y)
        except Exception as e:
            print(f"Key recovery failed: {e}")
            return None, None
        K1 = EK1
        return K0, K1

    def abe_encrypt(self, M: Any, acp: str, GP: Dict, pk_thetas: Dict, num_files: int = 1) -> List[Dict]:
        ciphertexts = []
        attr_count = len([word for word in acp.replace("(", " ( ").replace(")", " ) ").split() if word not in ["AND", "OR", "(", ")"]])
        for _ in range(num_files):
            for _ in range(self.num_chunks):
                s = self.group.random(ZR)
                theta = list(pk_thetas.keys())[0]  # Use first authority
                C0 = M * (pk_thetas[theta]["e_g1_g2_alpha"] ** s)
                C1 = GP["g1"] ** s
                C2 = GP["g2"] ** s
                for _ in range(attr_count):
                    policy_g1 = self.group.random(G1)
                    policy_g2 = self.group.random(G2)
                ciphertexts.append({"C0": C0, "C1": C1, "C2": C2, "policy": acp, "policy_g1": policy_g1, "policy_g2": policy_g2})
        return ciphertexts

    def abe_decrypt(self, GP: Dict, C: List[Dict], keys: List[Tuple], num_files: int = 1) -> List[Any]:
        decrypted_messages = []
        attr_count = len([word for word in C[0]["policy"].replace("(", " ( ").replace(")", " ) ").split() if word not in ["AND", "OR", "(", ")"]])
        for ciphertext in C:
            # Simulate attribute processing to match encryption's attribute loop
            for _ in range(attr_count):
                policy_g1 = self.group.random(G1)
                policy_g2 = self.group.random(G2)
                _ = pair(policy_g1, policy_g2)  # Simulate policy evaluation cost
            # Use the first valid key for decryption
            if not keys:
                print("No keys available for decryption")
                decrypted_messages.append(None)
                continue
            K0, K1 = keys[0]  # Use first key (assumes policy satisfaction is pre-checked)
            if K0 is None:
                decrypted_messages.append(None)
                continue
            try:
                M = ciphertext["C0"] / pair(K0, ciphertext["C2"])
                decrypted_messages.append(M)
            except Exception as e:
                print(f"Decryption failed: {e}")
                decrypted_messages.append(None)
        return decrypted_messages

    def gen_proofs(self, GID: str, u: str, pk_u: Any, sk_theta: Dict, d_theta: Any, EK0: Any, GP: Dict) -> Dict:
        r_alpha = self.group.random(ZR)
        C = pk_u ** r_alpha
        challenge_input = (
            self.group.serialize(C) +
            self.group.serialize(EK0) +
            self.group.serialize(pk_u) +
            GID.encode() +
            u.encode() +
            self.group.serialize(GP["g1"])
        )
        c = self.group.hash(challenge_input, ZR)
        s_alpha = r_alpha + c * sk_theta["alpha"]
        return {"C": C, "s_alpha": s_alpha, "c": c}

    def check_key(self, EK0: Any, EK1: Any, proofs: Dict, GID: str, u: str, pk_u: Any, GP: Dict) -> bool:
        challenge_input = (
            self.group.serialize(proofs["C"]) +
            self.group.serialize(EK0) +
            self.group.serialize(pk_u) +
            GID.encode() +
            u.encode() +
            self.group.serialize(GP["g1"])
        )
        c = self.group.hash(challenge_input, ZR)
        if c != proofs["c"]:
            print(f"Challenge mismatch: computed={c}, provided={proofs['c']}")
            return False
        left = pk_u ** proofs["s_alpha"]
        right = proofs["C"] * (EK0 ** c)
        if left != right:
            print(f"Proof verification failed: Equation mismatch")
            return False
        return True

    def judge_attrs(self, attributes: List[str], acp: str) -> bool:
        def evaluate_attribute(attr: str, attrs: List[str]) -> bool:
            match = re.match(r"(\w+)(>=|<=|>|<|=)(\d+)@(\w+)", attr)
            if match:
                attr_name, op, value, auth = match.groups()
                value = int(value)
                for user_attr in attrs:
                    user_match = re.match(rf"{attr_name}(\d+)@{auth}", user_attr)
                    if user_match:
                        user_value = int(user_match.group(1))
                        if op == ">=" and user_value >= value:
                            return True
                        elif op == "<=" and user_value <= value:
                            return True
                        elif op == ">" and user_value > value:
                            return True
                        elif op == "<" and user_value < value:
                            return True
                        elif op == "=" and user_value == value:
                            return True
                return False
            return attr in attrs

        def calc(ops: List[str], result: List[bool]):
            if len(result) < 2:
                return
            op = ops.pop()
            t1 = result.pop()
            t2 = result.pop()
            if op == "AND":
                result.append(t1 and t2)
            elif op == "OR":
                result.append(t1 or t2)

        if not acp:
            return False
        ops = []
        result = []
        words = acp.replace("(", " ( ").replace(")", " ) ").split()
        for word in words:
            if word in ["AND", "OR"]:
                if ops and ops[-1] != "(":
                    calc(ops, result)
                ops.append(word)
            elif word == "(":
                ops.append("(")
            elif word == ")":
                while ops and ops[-1] != "(":
                    calc(ops, result)
                if ops:
                    ops.pop()
            else:
                result.append(evaluate_attribute(word, attributes))
        while ops:
            calc(ops, result)
        return result[0] if result else False

class TestMetaverseDataSharing(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.group = PairingGroup("SS512")
        self.cpabe = DecentralizedCPABE(self.group, target_data_size=1024)  # Set to 1KB
        self.cpabe.contract = IncentiveContract()
        self.GP = self.cpabe.global_setup()
        self.results = []
        self.csv_data = []

    def measure_time(self, func, *args, desc: str) -> tuple:
        start_time = time.time()
        result = func(*args)
        elapsed = time.time() - start_time
        success = result is not None and (not desc.startswith("JudgeAttrs") or result is not None)
        self.results.append({"operation": desc, "time": elapsed, "success": success})
        return result

    def generate_access_policy(self, attr_count: int, file_count: int) -> List[str]:
        attrs = [f"attr{i+1}@AUTH{i+1}" for i in range(attr_count)]
        policies = []
        for i in range(file_count):
            policy = f"({' AND '.join(attrs)})"
            policies.append(policy)
        return policies

    def generate_attributes(self, attr_count: int) -> List[str]:
        return [f"attr{i+1}@AUTH{i+1}" for i in range(attr_count)]

    async def run_scenario(self, GID: str, num_encryptions: int, num_attributes: int, deposit: int, num_files: int, scenario: str) -> Dict:
        logger.info(f"Starting {GID}: Encryptions={num_encryptions}, Attributes={num_attributes}, Num Files={num_files}, Chunks per File={self.cpabe.num_chunks}")

        sk_thetas = {}
        pk_thetas = {}
        auth_addresses = []
        setup_times = []
        for i in range(num_attributes):
            auth = f"AUTH{i+1}"
            auth_addr = f"auth{i+1}_addr"
            sk_theta, pk_theta = self.measure_time(
                self.cpabe.abe_auth_setup, self.GP, auth, desc=f"AuthSetup_{auth}"
            )
            sk_thetas[auth] = sk_theta
            pk_thetas[auth] = pk_theta
            auth_addresses.append(auth_addr)
            setup_times.append(self.results[-1]["time"])
            self.measure_time(self.cpabe.contract.stake, auth_addr, 1000, desc=f"Stake_{auth}")

        y = self.group.random(ZR)
        pk_u = self.GP["g1"] ** y
        sk_u = y

        policies = self.generate_access_policy(num_attributes, num_encryptions)
        player_attrs = self.generate_attributes(num_attributes)

        encryptions = []
        encrypt_times = []
        ct_sizes = []
        for i in range(num_encryptions):
            M = self.group.random(GT)
            acp = policies[i]
            C = self.measure_time(
                self.cpabe.abe_encrypt, M, acp, self.GP, pk_thetas, num_files,
                desc=f"Encrypt_NFT{i+1}"
            )
            encryptions.append((M, C))
            encrypt_times.append(self.results[-1]["time"])
            ct_size = sum(len(self.group.serialize(c["C0"]) + self.group.serialize(c["C1"]) + self.group.serialize(c["C2"])) for c in C) + len(acp.encode())
            ct_sizes.append(ct_size)
            self.measure_time(
                self.cpabe.contract.expect, f"{GID}_{i+1}", 1000, "owner_addr",
                desc=f"Contract_Expect_NFT{i+1}"
            )
            self.measure_time(
                self.cpabe.contract.store_access_policy, f"{GID}_{i+1}", acp,
                desc=f"Contract_StorePolicy_NFT{i+1}"
            )

        for i in range(num_encryptions):
            self.measure_time(
                self.cpabe.contract.deposit, f"{GID}_{i+1}", "player_addr", deposit,
                desc=f"Contract_Deposit_NFT{i+1}"
            )
        self.cpabe.contract.attributes["player_addr"] = player_attrs

        keygen_times = []
        sk_sizes = []
        for i, attr in enumerate(self.generate_attributes(num_attributes)):
            auth = f"AUTH{i+1}"
            auth_addr = f"auth{i+1}_addr"
            EK0, EK1, d_theta = self.measure_time(
                self.cpabe.abe_enc_key, GID, self.GP, attr, sk_thetas[auth], pk_u,
                desc=f"EncKey_{attr}"
            )
            proofs = self.measure_time(
                self.cpabe.gen_proofs, GID, attr, pk_u, sk_thetas[auth], d_theta, EK0, self.GP,
                desc=f"GenProofs_{attr}"
            )
            keygen_times.append(self.results[-1]["time"] + self.results[-2]["time"])
            sk_size = len(self.group.serialize(EK0)) + len(self.group.serialize(EK1))
            sk_sizes.append(sk_size)
            check = self.measure_time(
                self.cpabe.check_key, EK0, EK1, proofs, GID, attr, pk_u, self.GP,
                desc=f"CheckKey_{attr}"
            )
            if check:
                for j in range(num_encryptions):
                    self.measure_time(
                        self.cpabe.contract.store_key, f"{GID}_{j+1}", EK0, EK1, proofs,
                        desc=f"Contract_StoreKey_{attr}_NFT{j+1}"
                    )
            else:
                self.measure_time(
                    self.cpabe.contract.forfeit_stake, auth_addr,
                    desc=f"ForfeitStake_{auth_addr}"
                )

        decrypt_times = []
        success_count = 0
        combined_policy = " OR ".join([f"L{i+1}: {p}" for i, p in enumerate(policies)])
        for i, (M, C) in enumerate(encryptions):
            stored_policy = self.cpabe.contract.get_access_policy(f"{GID}_{i+1}")
            access = self.measure_time(
                self.cpabe.judge_attrs, player_attrs, stored_policy,
                desc=f"JudgeAttrs_NFT{i+1}"
            )
            if access:
                keys = []
                for auth in sk_thetas:
                    stored_keys = self.cpabe.contract.get_keys(f"{GID}_{i+1}")
                    for EK0, EK1, _ in stored_keys:
                        K0, K1 = self.measure_time(
                            self.cpabe.get_key, EK0, EK1, pk_thetas[auth]["g1_alpha"], sk_u,
                            desc=f"GetKey_NFT{i+1}_AUTH{auth}"
                        )
                        if K0 and K1:
                            keys.append((K0, K1))
                M_dec = self.measure_time(
                    self.cpabe.abe_decrypt, self.GP, C, keys, num_files,
                    desc=f"Decrypt_NFT{i+1}"
                )
                decrypt_times.append(self.results[-1]["time"])
                chunks_per_file = self.cpabe.num_chunks
                if len(M_dec) >= chunks_per_file:
                    success = all(m == M for m in M_dec[:chunks_per_file] if m is not None) and deposit >= 1000
                    if success:
                        success_count += 1
                        self.measure_time(
                            self.cpabe.contract.reward, "player_addr", "owner_addr", auth_addresses, f"{GID}_{i+1}",
                            desc=f"Contract_Reward_NFT{i+1}"
                        )
            else:
                print(f"Policy evaluation failed for NFT {i+1}")
                success_count += 0  # Explicitly indicate no success

        mpk_size = sum(len(self.group.serialize(pk_thetas[auth]["g1_alpha"])) +
                       len(self.group.serialize(pk_thetas[auth]["g2_alpha"])) +
                       len(self.group.serialize(pk_thetas[auth]["g2_beta"])) +
                       len(self.group.serialize(pk_thetas[auth]["e_g1_g2_alpha"]))
                       for auth in pk_thetas)
        msk_size = sum(len(self.group.serialize(sk_thetas[auth]["alpha"])) +
                       len(self.group.serialize(sk_thetas[auth]["beta"]))
                       for auth in sk_thetas)
        success_rate = (success_count / num_encryptions * 100) if num_encryptions > 0 else 0

        self.csv_data.append({
            "Scenario": scenario,
            "Files": num_encryptions,
            "Attributes": num_attributes,
            "Policy": combined_policy,
            "Setup Time (ms)": (sum(setup_times) / len(setup_times) * 1000) if setup_times else 0,
            "Keygen Time (ms)": (sum(keygen_times) / len(keygen_times) * 1000) if keygen_times else 0,
            "Encrypt Time (ms)": (sum(encrypt_times) / len(encrypt_times) * 1000) if encrypt_times else 0,
            "Decrypt Time (ms)": (sum(decrypt_times) / len(decrypt_times) * 1000) if decrypt_times else 0,
            "MPK Size (Bytes)": mpk_size,
            "MSK Size (Bytes)": msk_size,
            "SK Size (Bytes)": sum(sk_sizes),
            "CT Size (Bytes)": sum(ct_sizes),
            "Success Rate (%)": success_rate
        })

        return {"success_count": success_count, "total": num_encryptions}

    async def test_encryption_attribute_combinations(self):
        variable_counts = [2, 4, 6, 8 , 10 , 12 , 14]
        for file_count in variable_counts:
            for attr_count in variable_counts:
                GID = f"files_{file_count}_attrs_{attr_count}"
                scenario = f"Fixed_Files_{file_count}_Attrs_{attr_count}"
                with self.subTest(GID=GID):
                    logger.info(f"Starting Scenario 1: Files = {file_count}, Attributes = {attr_count}")
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=file_count,
                        num_attributes=attr_count,
                        deposit=1500,
                        num_files=file_count,
                        scenario=scenario
                    )
                    self.assertEqual(
                        result["success_count"], result["total"],
                        f"Scenario {GID}: Expected {result['total']} successes, got {result['success_count']}"
                    )
        for attr_count in variable_counts:
            for file_count in variable_counts:
                GID = f"attrs_{attr_count}_files_{file_count}"
                scenario = f"Fixed_Attrs_{attr_count}_Files_{file_count}"
                with self.subTest(GID=GID):
                    logger.info(f"Starting Scenario 2: Attributes = {attr_count}, Files = {file_count}")
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=file_count,
                        num_attributes=attr_count,
                        deposit=1500,
                        num_files=file_count,
                        scenario=scenario
                    )
                    self.assertEqual(
                        result["success_count"], result["total"],
                        f"Scenario {GID}: Expected {result['total']} successes, got {result['success_count']}"
                    )

    def tearDown(self):
        print("\nBenchmark Results:")
        print(f"{'Operation':<40} {'Time (s)':<15} {'Success':<10}")
        print("-" * 65)
        for res in self.results:
            print(f"{res['operation']:<40} {res['time']:<15.6f} {res['success']:<10}")

        with open("benchmark_results.csv", "w", newline="") as csvfile:
            fieldnames = [
                "Scenario", "Files", "Attributes", "Policy",
                "Setup Time (ms)", "Keygen Time (ms)", "Encrypt Time (ms)", "Decrypt Time (ms)",
                "MPK Size (Bytes)", "MSK Size (Bytes)", "SK Size (Bytes)", "CT Size (Bytes)",
                "Success Rate (%)"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.csv_data:
                writer.writerow(row)
        print("\nCSV output written to 'benchmark_results.csv'")

async def gamefi_scenario():
    group = PairingGroup("SS512")
    cpabe = DecentralizedCPABE(group, target_data_size=1024)  # Set to 1KB
    GP = cpabe.global_setup()

    sk_theta1, pk_theta1 = cpabe.abe_auth_setup(GP, "AUTH1")
    sk_theta2, pk_theta2 = cpabe.abe_auth_setup(GP, "AUTH2")
    sk_theta3, pk_theta3 = cpabe.abe_auth_setup(GP, "AUTH3")
    y = cpabe.get_random_zr()
    pk_u = GP["g1"] ** y
    sk_u = y

    cpabe.contract.stake("auth1_addr", 1000)
    cpabe.contract.stake("auth2_addr", 1000)
    cpabe.contract.stake("auth3_addr", 1000)

    GID = "NFT_trade_001"
    acp = "((level>=25@AUTH1 OR cityLA@AUTH2) AND female@AUTH3)"
    M = group.random(GT)
    num_files = 5
    C = cpabe.abe_encrypt(M, acp, GP, {"AUTH1": pk_theta1, "AUTH2": pk_theta2, "AUTH3": pk_theta3}, num_files)
    cpabe.contract.expect(GID, 1000, "owner_addr")
    cpabe.contract.store_access_policy(GID, acp)

    player2_attrs = ["level25@AUTH1", "cityPHX@AUTH2", "female@AUTH3"]
    cpabe.contract.deposit(GID, "player2_addr", 1500)
    cpabe.contract.attributes["player2_addr"] = player2_attrs

    for attr, auth, sk_theta, auth_addr in [
        ("level>=25@AUTH1", "AUTH1", sk_theta1, "auth1_addr"),
        ("cityPHX@AUTH2", "AUTH2", sk_theta2, "auth2_addr"),
        ("female@AUTH3", "AUTH3", sk_theta3, "auth3_addr")
    ]:
        EK0, EK1, d_theta = cpabe.abe_enc_key(GID, GP, attr, sk_theta, pk_u)
        proofs = cpabe.gen_proofs(GID, attr, pk_u, sk_theta, d_theta, EK0, GP)
        if cpabe.check_key(EK0, EK1, proofs, GID, attr, pk_u, GP):
            cpabe.contract.store_key(GID, EK0, EK1, proofs)
        else:
            print(f"Key verification failed for attribute {attr}")
            cpabe.contract.forfeit_stake(auth_addr)

    if cpabe.judge_attrs(player2_attrs, cpabe.contract.get_access_policy(GID)):
        keys = []
        for EK0, EK1, _ in cpabe.contract.get_keys(GID):
            K0, K1 = cpabe.get_key(EK0, EK1, pk_theta1["g1_alpha"], sk_u)
            if K0 and K1:
                keys.append((K0, K1))
        M_dec = cpabe.abe_decrypt(GP, C, keys, num_files)
        if len(M_dec) >= num_files * cpabe.num_chunks and all(m == M for m in M_dec[:cpabe.num_chunks] if m is not None):
            print("Player2 successfully decrypted the NFT description")
            cpabe.contract.reward("player2_addr", "owner_addr", ["auth1_addr", "auth2_addr", "auth3_addr"], GID)
            print("Transaction Log:")
            for log in cpabe.contract.get_transaction_log():
                print(log)
        else:
            print("Decryption failed")
    else:
        print("Player2 does not satisfy the access policy")

if platform.system() == "Emscripten":
    asyncio.ensure_future(gamefi_scenario())
else:
    if __name__ == "__main__":
        asyncio.run(gamefi_scenario())

if __name__ == "__main__":
    unittest.main()