import unittest
import time
import asyncio
import csv
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from access_control import CPABE, SimulatedIPFS, SimulatedBlockchain, aes_encrypt, aes_decrypt
import uuid
from typing import List, Dict, Tuple

class TestCPABE(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.group = PairingGroup('SS512')
        self.max_attributes = 14
        self.cpabe = CPABE(max_attributes=self.max_attributes)
        self.ipfs = SimulatedIPFS()
        self.blockchain = SimulatedBlockchain()
        self.results = []
        self.encryption_counts = [2, 4, 6, 8, 10, 12, 14]
        self.attribute_counts = [2, 4, 6, 8, 10, 12, 14]
        self.csv_data = []

    def measure_time(self, func, *args, desc: str) -> tuple:
        start_time = time.time()
        result = func(*args)
        elapsed = time.time() - start_time
        success = result is not None
        self.results.append({"operation": desc, "time": elapsed, "success": success})
        return result

    def generate_access_policy(self, attr_count: int, file_count: int) -> List[str]:
        available_attrs = [f"attr{i+1}" for i in range(attr_count)]
        policies = []
        for _ in range(file_count):
            policy = f"({' AND '.join(available_attrs)})"
            policies.append(policy)
        return policies

    def generate_attributes(self, attr_count: int) -> List[str]:
        return [f"attr{i+1}" for i in range(attr_count)]

    def judge_attrs(self, user_attrs: List[str], policy: str) -> bool:
        required_attrs = [attr.strip() for attr in policy.strip('()').split(' AND ')]
        return all(attr in user_attrs for attr in required_attrs)

    async def run_scenario(self, GID: str, num_encryptions: int, num_attributes: int, deposit: int, scenario: str) -> Dict:
        # System setup
        PK, MK = self.measure_time(self.cpabe.setup, 128, desc="Setup")

        # Data owner actions
        address_do = f"DO_Addr_{GID}"
        message = "Sensitive Data"
        W = "keyword"
        policies = self.generate_access_policy(num_attributes, num_encryptions)
        user_attrs = self.generate_attributes(num_attributes)
        print(f"Debug: GID={GID}, Scenario={scenario}, Player attributes: {user_attrs}, Policies: {policies}")

        # Encrypt multiple files
        encryptions = []
        encrypt_times = []
        ct_sizes = []
        for i in range(num_encryptions):
            fid = f"{GID}_{i+1}"
            P = policies[i]
            print(f"Debug: NFT{i+1} - Policy: {P}")
            try:
                CT_1 = self.measure_time(self.cpabe.pro_enc, PK, P, desc=f"ProEnc_NFT{i+1}")
                CT, Omega_i, I_w, ck = self.measure_time(
                    self.cpabe.encrypt, PK, W, CT_1, P, desc=f"Encrypt_NFT{i+1}"
                )
                encrypted_file = self.measure_time(
                    aes_encrypt, message, ck, desc=f"AESEncrypt_NFT{i+1}"
                )
                HD = self.measure_time(self.ipfs.store, fid, encrypted_file, desc=f"IPFSStore_NFT{i+1}")
                success = self.measure_time(
                    self.blockchain.storage, address_do, fid, CT, HD, I_w, Omega_i,
                    desc=f"BlockchainStore_NFT{i+1}"
                )
                print(f"Debug: NFT{i+1} - Stored Omega_i: {Omega_i}, FID: {fid}")
                encryptions.append((message, CT, HD, ck))
                encrypt_times.append(self.results[-4]["time"] + self.results[-3]["time"])  # pro_enc + encrypt
                ct_size = (sum(len(self.group.serialize(c)) for c in [CT['C'], CT['C_0'], CT['C_1'], CT['C_2']]) +
                           sum(len(self.group.serialize(c)) for c in CT['C_y'].values()) +
                           len(P.encode()))
                ct_sizes.append(ct_size)
            except Exception as e:
                print(f"Debug: NFT{i+1} - Encryption failed: {e}")
                continue

        # Data user actions
        address_du = f"DU_Addr_{GID}"
        SK = self.measure_time(self.cpabe.key_gen, PK, MK, user_attrs, desc="KeyGen")
        keygen_time = self.results[-1]["time"]  # Store keygen time explicitly
        print(f"Debug: KeyGen - SK components: S_i keys for {list(SK['S_i'].keys())}")
        deadline = 40
        self.measure_time(
            self.blockchain.set_usk, address_do, address_du, SK, deadline,
            desc="SetUserKey"
        )

        # Decrypt directly (bypass search to isolate CP-ABE issue)
        decrypt_times = []
        success_count = 0
        now_time = 30
        combined_policy = " OR ".join([f"L{i+1}: {p}" for i, p in enumerate(policies)])
        for i, (original_message, CT, HD, ck) in enumerate(encryptions):
            fid = f"{GID}_{i+1}"
            access = self.judge_attrs(user_attrs, policies[i])
            print(f"Debug: NFT{i+1} - Access granted: {access}, Policy: {policies[i]}, Attributes: {user_attrs}")
            if not access:
                print(f"Debug: NFT{i+1} - Access denied, skipping decryption")
                continue
            try:
                CT_retrieved, HD_retrieved = CT, HD
                print(f"Debug: NFT{i+1} - Using stored CT and HD: {HD_retrieved}")
                SK_prime = SK
                CT_2 = self.measure_time(
                    self.cpabe.pro_dec, SK_prime, CT_retrieved, policies[i], desc=f"ProDec_NFT{i+1}"
                )
                print(f"Debug: NFT{i+1} - CT_2 computed: {self.group.serialize(CT_2)[:16].hex()}")
                ck_prime = self.measure_time(
                    self.cpabe.decrypt, CT_2, desc=f"Decrypt_NFT{i+1}"
                )
                print(f"Debug: NFT{i+1} - ck: {ck.hex()}, ck_prime: {ck_prime.hex()}")
                decrypted_file = self.measure_time(
                    aes_decrypt, self.ipfs.retrieve(HD_retrieved), ck_prime,
                    desc=f"AESDecrypt_NFT{i+1}"
                )
                decrypt_times.append(self.results[-3]["time"] + self.results[-2]["time"])  # pro_dec + decrypt
                success = decrypted_file == original_message and deposit >= 1000
                print(f"Debug: NFT{i+1} - Decryption success: {success}, Decrypted: {decrypted_file}, Expected: {original_message}")
                if success:
                    success_count += 1
            except Exception as e:
                print(f"Debug: NFT{i+1} - Decryption failed: {e}")
                continue

        # Compute sizes
        mpk_size = (len(self.group.serialize(PK['g'])) +
                    len(self.group.serialize(PK['g_alpha'])) +
                    len(self.group.serialize(PK['g_beta'])) +
                    len(self.group.serialize(PK['e_g_g_alpha'])) +
                    sum(len(self.group.serialize(v)) for v in PK['AK'].values()))
        msk_size = (len(self.group.serialize(MK['alpha'])) +
                    len(self.group.serialize(MK['beta'])) +
                    sum(len(self.group.serialize(v)) for v in MK['v'].values()))
        sk_size = (len(self.group.serialize(SK['S_1'])) +
                   len(self.group.serialize(SK['S_2'])) +
                   sum(len(self.group.serialize(v)) for v in SK['S_i'].values()))
        success_rate = (success_count / num_encryptions * 100) if num_encryptions > 0 else 0

        # Store CSV data
        self.csv_data.append({
            "Scenario": scenario,
            "Files": num_encryptions,
            "Attributes": num_attributes,
            "Policy": combined_policy,
            "Setup Time (s)": self.results[0]["time"],
            "Keygen Time (s)": keygen_time,
            "Encrypt Time (s)": sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0,
            "Decrypt Time (s)": sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0,
            "MPK Size (Bytes)": mpk_size,
            "MSK Size (Bytes)": msk_size,
            "SK Size (Bytes)": sk_size,
            "CT Size (Bytes)": sum(ct_sizes) if ct_sizes else 0,
            "Success Rate (%)": success_rate
        })

        return {"success_count": success_count, "total": num_encryptions}

    async def test_fixed_files_varying_attributes(self):
        for enc_count in self.encryption_counts:
            for attr_count in self.attribute_counts:
                with self.subTest(enc_count=enc_count, attr_count=attr_count):
                    GID = f"NFT_fixed_files_enc{enc_count}_attr{attr_count}"
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=enc_count,
                        num_attributes=attr_count,
                        deposit=1500,
                        scenario=f"Fixed Files ({enc_count})"
                    )
                    self.assertEqual(
                        result["success_count"], result["total"],
                        f"Scenario {GID}: Expected {result['total']} successes, got {result['success_count']}"
                    )

    async def test_fixed_attributes_varying_files(self):
        for attr_count in self.attribute_counts:
            for enc_count in self.encryption_counts:
                with self.subTest(enc_count=enc_count, attr_count=attr_count):
                    GID = f"NFT_fixed_attrs_attr{attr_count}_enc{enc_count}"
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=enc_count,
                        num_attributes=attr_count,
                        deposit=1500,
                        scenario=f"Fixed Attributes ({attr_count})"
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
                "Scenario", "Files", "Attributes", "Policy", "Setup Time (s)", "Keygen Time (s)",
                "Encrypt Time (s)", "Decrypt Time (s)", "MPK Size (Bytes)", "MSK Size (Bytes)",
                "SK Size (Bytes)", "CT Size (Bytes)", "Success Rate (%)"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in self.csv_data:
                writer.writerow(row)
        print("\nCSV output written to 'benchmark_results.csv'")

if __name__ == "__main__":
    unittest.main()