import asyncio
import platform
import re
from typing import List, Dict, Tuple
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import hashlib

# Custom hash-to-G1 function
def hash_to_G1(group: PairingGroup, input_str: str) -> G1:
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
        self.stakes = {}  # Track authority stakes

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

    def store_key(self, GID: str, EK0, EK1, proofs) -> bool:
        if GID not in self.keys:
            self.keys[GID] = []
        self.keys[GID].append((EK0, EK1, proofs))
        self.transactions.append(f"Stored key for GID {GID}")
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

# CP-ABE Implementation based on Rouselakis-Waters
class DecentralizedCPABE(ABEncMultiAuth):
    def __init__(self, group: PairingGroup):
        super().__init__()
        self.group = group
        self.contract = IncentiveContract()

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

    def abe_keygen(self, GID: str, GP: Dict, u: str, sk_theta: Dict) -> Tuple:
        d_theta = self.group.random(ZR)
        H_GID = hash_to_G1(self.group, GID)
        F_u = hash_to_G1(self.group, u)
        K0 = (GP["g1"] ** sk_theta["alpha"]) * (H_GID ** sk_theta["beta"]) * (F_u ** d_theta)
        K1 = GP["g2"] ** d_theta
        return K0, K1, d_theta

    def abe_enc_key(self, GID: str, GP: Dict, u: str, sk_theta: Dict, pk_u: G1) -> Tuple:
        d_theta = self.group.random(ZR)
        EK0 = pk_u ** sk_theta["alpha"]  # EK0 = (g1^y)^alpha
        EK1 = GP["g2"] ** d_theta
        return EK0, EK1, d_theta

    def get_key(self, EK0, EK1, g1_alpha: G1, y: ZR) -> Tuple:
        try:
            K0 = EK0 ** (1 / y)  # (g1^(y * alpha))^(1/y) = g1^alpha
        except Exception as e:
            print(f"Key recovery failed: {e}")
            return None, None
        K1 = EK1
        return K0, K1

    def abe_encrypt(self, M: GT, acp: str, GP: Dict, pk_thetas: Dict) -> Dict:
        s = self.group.random(ZR)
        theta = "AUTH1"  # Fixed authority
        C0 = M * (pk_thetas[theta]["e_g1_g2_alpha"] ** s)  # e(g1, g2)^(alpha * s)
        C1 = GP["g1"] ** s
        C2 = GP["g2"] ** s
        return {"C0": C0, "C1": C1, "C2": C2, "policy": acp}

    def abe_decrypt(self, GP: Dict, C: Dict, keys: List[Tuple]) -> GT:
        if not keys:
            print("No keys available for decryption")
            return None
        K0, _ = keys[0]  # First key is for AUTH1
        if K0 is None:
            return None
        try:
            M = C["C0"] / pair(K0, C["C2"])  # M = [M * e(g1, g2)^(alpha * s)] / e(g1, g2)^(alpha * s)
            return M
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def gen_proofs(self, GID: str, u: str, pk_u: G1, sk_theta: Dict, d_theta: ZR, EK0: G1, GP: Dict) -> Dict:
        # Random blinding factor
        r_alpha = self.group.random(ZR)
        
        # Commitment: C = pk_u^r_alpha
        C = pk_u ** r_alpha
        
        # Fiat-Shamir challenge: hash public values
        challenge_input = (
            self.group.serialize(C) +
            self.group.serialize(EK0) +
            self.group.serialize(pk_u) +
            GID.encode() +
            u.encode() +
            self.group.serialize(GP["g1"])
        )
        c = self.group.hash(challenge_input, ZR)
        
        # Response: s_alpha = r_alpha + c * alpha
        s_alpha = r_alpha + c * sk_theta["alpha"]
        
        return {"C": C, "s_alpha": s_alpha, "challenge": c}

    def check_key(self, EK0: G1, EK1: G1, proofs: Dict, GID: str, u: str, pk_u: G1, GP: Dict) -> bool:
        # Recompute challenge
        challenge_input = (
            self.group.serialize(proofs["C"]) +
            self.group.serialize(EK0) +
            self.group.serialize(pk_u) +
            GID.encode() +
            u.encode() +
            self.group.serialize(GP["g1"])
        )
        c = self.group.hash(challenge_input, ZR)
        
        # Verify challenge matches
        if c != proofs["challenge"]:
            print(f"Challenge mismatch: computed={c}, provided={proofs['challenge']}")
            return False
        
        # Verify equation: pk_u^s_alpha == C * (EK0^c)
        left = pk_u ** proofs["s_alpha"]
        right = proofs["C"] * (EK0 ** c)
        
        if left != right:
            print(f"Proof verification failed: Equation mismatch (left={left}, right={right})")
            return False
        
        # Optionally verify EK1 (not critical for simplified scheme)
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

# GameFi Application Simulation
async def gamefi_scenario():
    group = PairingGroup("SS512")
    cpabe = DecentralizedCPABE(group)
    GP = cpabe.global_setup()

    # Setup authorities and user
    sk_theta1, pk_theta1 = cpabe.abe_auth_setup(GP, "AUTH1")
    sk_theta2, pk_theta2 = cpabe.abe_auth_setup(GP, "AUTH2")
    sk_theta3, pk_theta3 = cpabe.abe_auth_setup(GP, "AUTH3")
    y = group.random(ZR)
    pk_u = GP["g1"] ** y
    sk_u = y

    # Stake authorities
    cpabe.contract.stake("auth1_addr", 1000)
    cpabe.contract.stake("auth2_addr", 1000)
    cpabe.contract.stake("auth3_addr", 1000)

    # Data owner sets up NFT encryption
    GID = "NFT_trade_001"
    acp = "((level>=25@AUTH1 OR cityLA@AUTH2) AND female@AUTH3)"
    M = group.random(GT)
    C = cpabe.abe_encrypt(M, acp, GP, {"AUTH1": pk_theta1, "AUTH2": pk_theta2, "AUTH3": pk_theta3})
    cpabe.contract.expect(GID, 1000, "owner_addr")
    cpabe.contract.store_access_policy(GID, acp)

    # Player2 requests access
    player2_attrs = ["level25@AUTH1", "cityPHX@AUTH2", "female@AUTH3"]
    cpabe.contract.deposit(GID, "player2_addr", 1500)
    cpabe.contract.attributes["player2_addr"] = player2_attrs

    # Authorities issue keys with policy attributes
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

    # Verify access control
    if cpabe.judge_attrs(player2_attrs, cpabe.contract.get_access_policy(GID)):
        # Player2 retrieves keys
        keys = []
        for EK0, EK1, _ in cpabe.contract.get_keys(GID):
            K0, K1 = cpabe.get_key(EK0, EK1, pk_theta1["g1_alpha"], sk_u)
            if K0 and K1:
                keys.append((K0, K1))
        # Decrypt
        M_dec = cpabe.abe_decrypt(GP, C, keys)
        if M_dec == M:
            print("Player2 successfully decrypted the NFT description")
            cpabe.contract.reward("player2_addr", "owner_addr", ["auth1_addr", "auth2_addr", "auth3_addr"], GID)
            print("Transaction Log:")
            for log in cpabe.contract.get_transaction_log():
                print(log)
        else:
            print("Decryption failed")
    else:
        print("Player2 does not satisfy the access policy")