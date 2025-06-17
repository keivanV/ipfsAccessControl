from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.hash_module import Hash
import random
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Simulated IPFS storage
class SimulatedIPFS:
    def __init__(self):
        self.storage = {}  # {fid: encrypted_file}

    def store(self, fid, encrypted_file):
        if not encrypted_file:
            raise ValueError("encrypted_file cannot be empty")
        self.storage[fid] = encrypted_file
        return fid

    def retrieve(self, fid):
        return self.storage.get(fid)

# Simulated Blockchain
class SimulatedBlockchain:
    def __init__(self):
        self.data_store = {}  # {fid: (CT, HD, I_w, Omega_i)}
        self.user_keys = {}  # {address_du: (E_SK, deadline)}
        self.access_logs = {}  # {address_du: (lockNum, lockTime, lastTime)}

    def storage(self, address_do, fid, CT, HD, I_w, Omega_i):
        if fid in self.data_store:
            return False
        self.data_store[fid] = (CT, HD, I_w, Omega_i)
        return True

    def set_usk(self, address_do, address_du, E_SK, deadline):
        if address_du in self.user_keys:
            return False
        self.user_keys[address_du] = (E_SK, deadline)
        self.access_logs[address_du] = (0, 0, 0)
        return True

    def get_usk(self, address_du):
        if address_du not in self.user_keys:
            raise Exception("Not qualified.")
        return self.user_keys[address_du]

    def search(self, address_du, token, now_time, interval=10):
        if address_du not in self.user_keys:
            raise Exception("Only DU can call it.")
        E_SK, deadline = self.user_keys[address_du]
        lockNum, lockTime, lastTime = self.access_logs[address_du]

        if now_time > deadline:
            raise Exception("Access deadline exceeded.")
        if lockTime > now_time:
            raise Exception("Account locked.")

        if lastTime != 0 and (now_time - lastTime) < interval:
            lockNum += 1
            lockTime = now_time + (2 ** (lockNum - 1))
            self.access_logs[address_du] = (lockNum, lockTime, lastTime)
            raise Exception("Illegal access.")
        else:
            self.access_logs[address_du] = (lockNum, lockTime, now_time)

        Omega_i_prime, T_w = token
        print(f"Searching with Omega_i_prime: {Omega_i_prime}")
        for fid, (CT, HD, I_w, Omega_i) in self.data_store.items():
            print(f"Checking FID: {fid}, Omega_i: {Omega_i}")
            if Omega_i == Omega_i_prime:
                print("Omega_i match found, verifying keyword...")
                if self.verify_keyword(I_w, T_w):
                    print("Keyword verification successful.")
                    return CT, HD
                else:
                    print("Keyword verification failed.")
            else:
                print("Omega_i mismatch.")
        raise Exception("No matching data found.")

    def verify_keyword(self, I_w, T_w):


        I_1, I_2 = I_w
        T_1, T_2 = T_w
        left = pair(I_1, T_2)
        right = pair(I_2, T_1)
        
        print(f"Keyword verify: left={left}, right={right}")
        return left == right

# CP-ABE Scheme
class CPABE:
    def __init__(self, max_attributes=14):
        self.group = PairingGroup('SS512')
        self.hash = Hash(self.group)
        self.g = self.group.random(G1)
        self.GP = {'g': self.g}
        self.max_attributes = max_attributes

    def setup(self, lambda_param):
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        U = [f"attr{i+1}" for i in range(self.max_attributes)]
        v = {attr: self.group.random(ZR) for attr in U}
        PK = {
            'g': self.g,
            'g_alpha': self.g ** alpha,
            'g_beta': self.g ** beta,
            'e_g_g_alpha': pair(self.g, self.g) ** alpha,
            'AK': {attr: self.g ** v[attr] for attr in U}
        }
        MK = {'alpha': alpha, 'beta': beta, 'v': v}
        return PK, MK

    def pro_enc(self, PK, P):
        k_1 = self.group.random(ZR)
        # Extract attributes from policy
        attrs = [attr.strip() for attr in P.strip('()').split(' AND ')]
        C_1_prime = PK['g'] ** k_1
        C_y_prime = {attr: PK['AK'][attr] ** k_1 for attr in attrs if attr in PK['AK']}
        CT_1 = {'C_1_prime': C_1_prime, 'C_y_prime': C_y_prime}
        return CT_1

    def encrypt(self, PK, W, CT_1, P):
        k_2 = self.group.random(ZR)
        s = self.group.random(ZR)
        H_W = self.hash.hashToZr(W)
        I_1 = PK['g'] ** s
        I_2 = PK['g'] ** (s / H_W)
        I_w = (I_1, I_2)
        K = self.group.random(GT)
        C = K * (PK['e_g_g_alpha'] ** k_2)
        C_0 = PK['g'] ** k_2
        C_1 = PK['g_beta'] ** k_2
        C_2 = PK['g'] ** self.hash.hashToZr(W)
        C_y = CT_1['C_y_prime']
        CT = {'C': C, 'C_0': C_0, 'C_1': C_1, 'C_2': C_2, 'C_y': C_y}
        Omega_i = "policy1"
        K_bytes = self.group.serialize(K)
        ck = K_bytes[:16]
        return CT, Omega_i, I_w, ck

    def key_gen(self, PK, MK, S):
        r = self.group.random(ZR)
        S_1 = PK['g_alpha'] * (PK['g_beta'] ** r)
        S_2 = PK['g'] ** r
        S_i = {attr: PK['g'] ** (r / MK['v'][attr]) for attr in S if attr in MK['v']}
        SK = {'S_1': S_1, 'S_2': S_2, 'S_i': S_i}
        return SK

    def token(self, PK, SK, W_prime):
        Omega_i_prime = "policy1"
        t = self.group.random(ZR)
        H_W_prime = self.hash.hashToZr(W_prime)
        T_1 = PK['g'] ** (t * H_W_prime)
        T_2 = PK['g'] ** t
        T_w = (T_1, T_2)
        return Omega_i_prime, T_w

    def pro_dec(self, SK_prime, CT, P):
        # Verify attributes against policy
        attrs = [attr.strip() for attr in P.strip('()').split(' AND ')]
        if not all(attr in SK_prime['S_i'] for attr in attrs):
            raise ValueError("User attributes do not satisfy policy")
        pair_C0_S1 = pair(CT['C_0'], SK_prime['S_1'])
        pair_C1_S2 = pair(CT['C_1'], SK_prime['S_2'])
        blinding_factor = pair_C0_S1 / pair_C1_S2
        CT_2 = CT['C'] / blinding_factor
        return CT_2

    def decrypt(self, CT_2):
        K_bytes = self.group.serialize(CT_2)
        ck_prime = K_bytes[:16]
        return ck_prime

    def revocation(self, S_bar):
        AK_bar = {attr: self.group.random(G1) for attr in S_bar}
        S_bar_components = {attr: self.group.random(ZR) for attr in S_bar}
        C_y_bar = {attr: self.group.random(G1) for attr in S_bar}
        return AK_bar, S_bar_components, C_y_bar

# Simulated AES encryption
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

# Simulated AES decryption
def aes_decrypt(ciphertext, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
        return pt.decode('utf-8')
    except ValueError:
        return None

# Main simulation
def main():
    try:
        # Initialize components
        cpabe = CPABE()
        blockchain = SimulatedBlockchain()
        ipfs = SimulatedIPFS()

        # System setup
        PK, MK = cpabe.setup(128)

        # Data owner actions
        address_do = "DO_Addr1"
        message = "Sensitive Data"
        W = "keyword"
        P = "((attr1 OR attr2) AND attr3 AND attr4)"
        CT_1 = cpabe.pro_enc(PK, P)
        CT, Omega_i, I_w, ck = cpabe.encrypt(PK, W, CT_1)  # Get ck from encrypt

        # Encrypt and store file
        fid = str(uuid.uuid4())
        encrypted_file = aes_encrypt(message, ck)
        HD = ipfs.store(fid, encrypted_file)

        # Store on blockchain
        if not blockchain.storage(address_do, fid, CT, HD, I_w, Omega_i):
            print("Storage failed: FID already exists.")
            return

        # Data user actions
        address_du = "DU_Addr1"
        S = ['attr1', 'attr3', 'attr4']
        SK = cpabe.key_gen(PK, MK, S)
        E_SK = SK
        deadline = 40
        if not blockchain.set_usk(address_do, address_du, E_SK, deadline):
            print("Failed to set user key.")
            return

        # Perform search
        W_prime = "keyword"
        token = cpabe.token(PK, SK, W_prime)
        now_time = 30
        try:
            CT_retrieved, HD_retrieved = blockchain.search(address_du, token, now_time)
            SK_prime = SK
            CT_2 = cpabe.pro_dec(SK_prime, CT_retrieved)
            ck_prime = cpabe.decrypt(CT_2)  # Pass CT_2 directly
            decrypted_file = aes_decrypt(ipfs.retrieve(HD_retrieved), ck_prime)
            if decrypted_file:
                print(f"Decrypted file: {decrypted_file}")
            else:
                print("Failed to decrypt file.")
        except Exception as e:
            print(f"Search error: {e}")

        # Attribute revocation
        S_bar = {'attr1'}
        AK_bar, S_bar_i, _ = cpabe.revocation(S_bar)
        print("Attributes revoked successfully.")

    except Exception as e:
        print(f"Main error: {e}")

if __name__ == "__main__":
    main()
