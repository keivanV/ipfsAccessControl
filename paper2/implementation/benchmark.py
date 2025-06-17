# --- in the name OF GOD ---
import unittest
import time
import asyncio
import csv
from metaverse_data_sharing import DecentralizedCPABE, IncentiveContract, hash_to_G1, PairingGroup, ZR, G1, G2, GT, pair
from typing import List, Dict, Tuple
import random

class TestMetaverseDataSharing(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.group = PairingGroup("SS512")
        self.cpabe = DecentralizedCPABE(self.group)
        self.cpabe.contract = IncentiveContract()  # Reset contract for each test
        self.GP = self.cpabe.global_setup()
        self.results = []
        self.encryption_counts = [2, 4, 6, 8, 10, 12, 14]
        self.attribute_counts = [2, 4, 6, 8, 10, 12, 14]
        self.csv_data = []

    def measure_time(self, func, *args, desc: str) -> tuple:
        start_time = time.time()
        result = func(*args)
        elapsed = time.time() - start_time
        success = result is not None and (not desc.startswith("JudgeAttrs") or result is not None)
        self.results.append({"operation": desc, "time": elapsed, "success": success})
        return result

    def generate_access_policy(self, attr_count: int, file_count: int) -> List[str]:
        # Generate a unique policy for each file: (attr1@AUTH1 AND attr2@AUTH2 AND ...)
        attrs = [f"attr{i+1}@AUTH{i+1}" for i in range(attr_count)]
        policies = []
        for i in range(file_count):
            policy = f"({' AND '.join(attrs)})"
            policies.append(policy)
        return policies

    def generate_attributes(self, attr_count: int) -> List[str]:
        return [f"attr{i+1}@AUTH{i+1}" for i in range(attr_count)]

    async def run_scenario(self, GID: str, num_encryptions: int, num_attributes: int, deposit: int) -> Dict:
        # Setup authorities
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

        # User key setup
        y = self.group.random(ZR)
        pk_u = self.GP["g1"] ** y
        sk_u = y

        # Generate access policies (one per file) and attributes
        policies = self.generate_access_policy(num_attributes, num_encryptions)
        player_attrs = self.generate_attributes(num_attributes)
        print(f"Debug: Player attributes: {player_attrs}")

        # Encrypt multiple NFTs
        encryptions = []
        encrypt_times = []
        ct_sizes = []
        for i in range(num_encryptions):
            M = self.group.random(GT)  # Fixed-size "file"
            acp = policies[i]  # Use unique policy for each NFT
            C = self.measure_time(
                self.cpabe.abe_encrypt, M, acp, self.GP, pk_thetas,
                desc=f"Encrypt_NFT{i+1}"
            )
            encryptions.append((M, C))
            encrypt_times.append(self.results[-1]["time"])
            ct_size = sum(len(self.group.serialize(c)) for c in [C["C0"], C["C1"], C["C2"]]) + len(acp.encode())
            ct_sizes.append(ct_size)
            self.measure_time(
                self.cpabe.contract.expect, f"{GID}_{i+1}", 1000, "owner_addr",
                desc=f"Contract_Expect_NFT{i+1}"
            )
            self.measure_time(
                self.cpabe.contract.store_access_policy, f"{GID}_{i+1}", acp,
                desc=f"Contract_StorePolicy_NFT{i+1}"
            )
            print(f"Debug: Stored policy for NFT{i+1}: {acp}")

        # Player deposits for all NFTs
        for i in range(num_encryptions):
            self.measure_time(
                self.cpabe.contract.deposit, f"{GID}_{i+1}", "player_addr", deposit,
                desc=f"Contract_Deposit_NFT{i+1}"
            )
        self.cpabe.contract.attributes["player_addr"] = player_attrs

        # Issue keys for attributes
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
            print(f"Debug: Key verification for {attr}: {check}")
            if check:
                for j in range(num_encryptions):
                    self.measure_time(
                        self.cpabe.contract.store_key, f"{GID}_{j+1}", EK0, EK1, proofs,
                        desc=f"Contract_StoreKey_{attr}_NFT{j+1}"
                    )
            else:
                print(f"Key verification failed for {attr}, forfeiting stake for {auth_addr}")
                self.measure_time(
                    self.cpabe.contract.forfeit_stake, auth_addr,
                    desc=f"ForfeitStake_{auth_addr}"
                )

        # Verify access and decrypt
        decrypt_times = []
        success_count = 0
        combined_policy = " OR ".join([f"L{i+1}: {p}" for i, p in enumerate(policies)])
        for i, (M, C) in enumerate(encryptions):
            stored_policy = self.cpabe.contract.get_access_policy(f"{GID}_{i+1}")
            print(f"Debug: NFT{i+1} - Retrieved policy: {stored_policy}, Expected: {policies[i]}")
            access = self.measure_time(
                self.cpabe.judge_attrs, player_attrs, stored_policy,
                desc=f"JudgeAttrs_NFT{i+1}"
            )
            print(f"Debug: NFT{i+1} - Access granted: {access}, Policy: {stored_policy}, Attributes: {player_attrs}")
            success = False
            if access:
                keys = []
                for auth in sk_thetas:
                    stored_keys = self.cpabe.contract.get_keys(f"{GID}_{i+1}")
                    print(f"Debug: NFT{i+1} - Retrieved {len(stored_keys)} keys for AUTH{auth}")
                    for EK0, EK1, _ in stored_keys:
                        K0, K1 = self.measure_time(
                            self.cpabe.get_key, EK0, EK1, pk_thetas[auth]["g1_alpha"], sk_u,
                            desc=f"GetKey_NFT{i+1}_AUTH{auth}"
                        )
                        if K0 and K1:
                            keys.append((K0, K1))
                print(f"Debug: NFT{i+1} - Collected {len(keys)} valid keys")
                M_dec = self.measure_time(
                    self.cpabe.abe_decrypt, self.GP, C, keys,
                    desc=f"Decrypt_NFT{i+1}"
                )
                decrypt_times.append(self.results[-1]["time"])
                success = M_dec == M and deposit >= 1000
                print(f"Debug: NFT{i+1} - Decryption success: {success}, M_dec == M: {M_dec == M}")
                if success:
                    success_count += 1
                    self.measure_time(
                        self.cpabe.contract.reward, "player_addr", "owner_addr", auth_addresses, f"{GID}_{i+1}",
                        desc=f"Contract_Reward_NFT{i+1}"
                    )
            else:
                print(f"Debug: NFT{i+1} - Access denied, skipping decryption")

        # Compute metrics
        mpk_size = sum(len(self.group.serialize(pk_thetas[auth]["g1_alpha"])) + 
                       len(self.group.serialize(pk_thetas[auth]["g2_alpha"])) +
                       len(self.group.serialize(pk_thetas[auth]["g2_beta"])) +
                       len(self.group.serialize(pk_thetas[auth]["e_g1_g2_alpha"]))
                       for auth in pk_thetas)
        msk_size = sum(len(self.group.serialize(sk_thetas[auth]["alpha"])) + 
                       len(self.group.serialize(sk_thetas[auth]["beta"]))
                       for auth in sk_thetas)
        success_rate = (success_count / num_encryptions * 100) if num_encryptions > 0 else 0

        # Store CSV data
        self.csv_data.append({
            "Files": num_encryptions,
            "Attributes": num_attributes,
            "Policy": combined_policy,
            "Setup Time (s)": sum(setup_times) / len(setup_times) if setup_times else 0,
            "Keygen Time (s)": sum(keygen_times) / len(keygen_times) if keygen_times else 0,
            "Encrypt Time (s)": sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0,
            "Decrypt Time (s)": sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0,
            "MPK Size (Bytes)": mpk_size,
            "MSK Size (Bytes)": msk_size,
            "SK Size (Bytes)": sum(sk_sizes),
            "CT Size (Bytes)": sum(ct_sizes),
            "Success Rate (%)": success_rate
        })

        return {"success_count": success_count, "total": num_encryptions}

    async def test_encryption_attribute_combinations(self):
        for enc_count in self.encryption_counts:
            for attr_count in self.attribute_counts:
                with self.subTest(enc_count=enc_count, attr_count=attr_count):
                    GID = f"NFT_trade_enc{enc_count}_attr{attr_count}"
                    result = await self.run_scenario(
                        GID=GID,
                        num_encryptions=enc_count,
                        num_attributes=attr_count,
                        deposit=1500
                    )
                    self.assertEqual(
                        result["success_count"], result["total"],
                        f"Scenario {GID}: Expected {result['total']} successes, got {result['success_count']}"
                    )

    def tearDown(self):
        # Print benchmark results
        print("\nBenchmark Results:")
        print(f"{'Operation':<40} {'Time (s)':<15} {'Success':<10}")
        print("-" * 65)
        for res in self.results:
            print(f"{res['operation']:<40} {res['time']:<15.6f} {res['success']:<10}")

        # Write CSV
        with open("benchmark_results.csv", "w", newline="") as csvfile:
            fieldnames = [
                "Files", "Attributes", "Policy", "Setup Time (s)", "Keygen Time (s)",
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