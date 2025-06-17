
# Fixed cr_fh.py for CR-FH-CPABE, ensuring correct access tree with num_attributes
import json
import random
import logging
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import time
from typing import List, Set, Dict, Optional, Tuple

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

class AccessTreeNode:
    """Represents a node in the hierarchical access tree."""
    def __init__(self, type_: str, gate_type: Optional[str] = None, attribute: Optional[str] = None, 
                 threshold: Optional[int] = None, level_node_id: Optional[str] = None):
        self.type = type_  # "leaf" or "gate"
        self.gate_type = gate_type  # "AND", "OR", or None for leaf nodes
        self.attribute = attribute  # Attribute for leaf nodes
        self.threshold = threshold  # k_x for gate nodes
        self.children: List['AccessTreeNode'] = []  # Child nodes
        self.index: Optional[int] = None  # Index in parent’s children
        self.parent: Optional['AccessTreeNode'] = None  # Parent node
        self.level_node_id = level_node_id  # L_i for level nodes
        self.q_x_0 = None  # Polynomial value at x=0

    def add_child(self, child: 'AccessTreeNode') -> None:
        """Add a child node and set its index and parent."""
        child.index = len(self.children)
        child.parent = self
        self.children.append(child)

    def __str__(self, indent: int = 0) -> str:
        """String representation of the node for debugging."""
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

def create_access_tree(num_attributes: int, attributes: List[str] = None) -> AccessTreeNode:
    import logging
    from typing import List
    # Default attributes if none provided
    if attributes is None or len(attributes) != num_attributes:
        attributes = [f"attr{i+1}" for i in range(num_attributes)]
    if len(attributes) != num_attributes:
        raise ValueError(f"Expected exactly {num_attributes} attributes, got {len(attributes)}")
    
    # Create root as an OR gate (threshold 1)
    root = AccessTreeNode("gate", gate_type="OR", threshold=1)
    
    # Add attributes in pairs: first two as OR, rest as AND gates
    for i in range(0, num_attributes, 2):
        if i < 2:
            # First pair (or single attribute) directly under root
            for j in range(min(2, num_attributes - i)):
                leaf = AccessTreeNode("leaf", attribute=attributes[i + j])
                root.add_child(leaf)
        else:
            # Subsequent pairs as AND gates under root
            if i < num_attributes:
                and_node = AccessTreeNode("gate", gate_type="AND", threshold=2)
                root.add_child(and_node)
                leaf1 = AccessTreeNode("leaf", attribute=attributes[i])
                and_node.add_child(leaf1)
                if i + 1 < num_attributes:
                    leaf2 = AccessTreeNode("leaf", attribute=attributes[i + 1])
                    and_node.add_child(leaf2)
    
    logging.debug(f"Created access tree with {num_attributes} attributes:\n{root}")
    return root

def get_leaves(node: AccessTreeNode) -> List[AccessTreeNode]:
    """Get all leaf nodes in the subtree."""
    leaves = []
    if node.type == "leaf":
        leaves.append(node)
    else:
        for child in node.children:
            leaves.extend(get_leaves(child))
    return leaves

class CRFHCPABE:
    """Collusion-Resistant File-Hierarchy CP-ABE scheme."""
    def __init__(self):
        self.group = PairingGroup('SS1024')  # Supersingular curve with 1024-bit base field
        self.G0 = self.group.random(G1)  # Generator in G1
        self.order = self.group.order()

    def H1(self, input_str: str) -> G1:
        """Hash function H1: {0,1}^* -> G1."""
        hash_val = hashlib.sha256(input_str.encode()).digest()
        x = self.group.hash(hash_val, ZR)
        return self.G0 ** x

    def H3(self, input_str: str) -> ZR:
        """Hash function H3: {0,1}^* -> Zp."""
        hash_val = hashlib.sha256(input_str.encode()).digest()
        return self.group.hash(hash_val, ZR)

    def setup(self) -> Tuple[Dict, Dict]:
        """Initialize public parameters (MPK) and master secret key (MSK)."""
        g = self.G0
        alpha = self.group.random(ZR)
        beta1 = self.group.random(ZR)
        beta2 = self.group.random(ZR)
        beta3 = self.group.random(ZR)
        theta = self.group.random(ZR)

        f1 = g ** beta1
        f2 = g ** beta2
        f3 = g ** beta3
        e_gg_alpha = pair(g, g) ** alpha

        MPK = {'g': g, 'f1': f1, 'f2': f2, 'f3': f3, 'e_gg_alpha': e_gg_alpha}
        MSK = {'alpha': alpha, 'beta1': beta1, 'beta2': beta2, 'beta3': beta3, 'theta': theta}
        logging.debug("Setup complete.")
        return MPK, MSK

    def keygen(self, MPK: Dict, MSK: Dict, attributes: Set[str], uid: str) -> Dict:
        """Generate private key for a user."""
        SK = {}
        r_i = self.group.random(ZR)
        omega1 = self.H3(uid)

        SK['D_i'] = MPK['g'] ** ((MSK['alpha'] + omega1) / MSK['beta1'])
        SK['E_i'] = MPK['g'] ** ((r_i + omega1) / MSK['beta2'])
        SK['E_i_prime'] = MPK['g'] ** ((r_i + omega1) / MSK['beta3'])

        for attr in attributes:
            r_i_j = self.group.random(ZR)
            SK[f'D_{attr}'] = (MPK['g'] ** (r_i + omega1)) * (self.H1(attr) ** r_i_j)
            SK[f'D_prime_{attr}'] = MPK['g'] ** r_i_j

        return SK

    def transform_keygen(self, MPK: Dict, MSK: Dict, SK: Dict, uid: str) -> Tuple[Dict, object]:
        """Generate transformation key for outsourced decryption."""
        TK = {}
        z_k = self.group.random(ZR)
        omega1 = self.H3(uid)

        TK['D_i'] = SK['D_i'] * (MPK['g'] ** z_k)
        TK['E_i'] = SK['E_i'] * (MPK['g'] ** z_k)
        TK['E_i_prime'] = SK['E_i_prime'] * (MPK['g'] ** z_k)
        for attr in SK:
            if attr.startswith('D_') and attr != 'D_i':
                TK[attr] = SK[attr] * (MPK['g'] ** z_k)
            elif attr.startswith('D_prime_'):
                TK[attr] = SK[attr] * (MPK['g'] ** z_k)

        RK = z_k
        return TK, RK

    def encrypt(self, MPK: Dict, messages: List[str], access_tree: AccessTreeNode) -> Dict:
        """Encrypt messages under the access tree."""
        CT = {}
        ck = [get_random_bytes(16) for _ in messages]
        s_i = [self.group.random(ZR) for _ in messages]
        epsilon = [self.group.random(ZR) for _ in messages]

        encrypted_messages = []
        for i, msg in enumerate(messages):
            cipher = AES.new(ck[i], AES.MODE_CBC)
            iv = cipher.iv
            ct = cipher.encrypt(pad(msg.encode(), AES.block_size))
            encrypted_messages.append((iv, ct))
        CT['encrypted_messages'] = encrypted_messages
        CT['ck'] = ck

        level_nodes = []
        self._assign_level_nodes(access_tree, level_nodes, 0)
        if len(level_nodes) != len(messages):
            # Assign the root as the level node for all messages
            level_nodes = [access_tree] * len(messages)
            for i, node in enumerate(level_nodes):
                node.level_node_id = f"L{i+1}"

        for i, node in enumerate(level_nodes):
            node_id = node.level_node_id
            s_plus_epsilon = s_i[i] + epsilon[i]
            ck_int = self.group.hash(ck[i][:20], ZR)
            CT[f'C_{node_id}'] = ck_int * (MPK['e_gg_alpha'] ** s_plus_epsilon)
            CT[f'C_prime_{node_id}'] = MPK['f1'] ** s_plus_epsilon
            CT[f'C_double_prime_{node_id}'] = MPK['f2'] ** s_plus_epsilon
            CT[f'C_triple_prime_{node_id}'] = MPK['f3'] ** s_i[i]

        self._assign_polynomials(access_tree, s_i)

        leaf_nodes = self._get_leaf_nodes(access_tree)
        for leaf in leaf_nodes:
            q_x_0 = leaf.q_x_0
            CT[f'C_{leaf.attribute}'] = MPK['g'] ** q_x_0
            CT[f'C_prime_{leaf.attribute}'] = self.H1(leaf.attribute) ** q_x_0

        CT['access_tree'] = access_tree
        return CT

    def _assign_level_nodes(self, node: AccessTreeNode, level_nodes: List[AccessTreeNode], index: int) -> int:
        if node.type == "gate" and node.level_node_id is not None:
            node.level_node_id = f"L{index + 1}"
            level_nodes.append(node)
            index += 1
        for child in node.children:
            index = self._assign_level_nodes(child, level_nodes, index)
        return index

    def _assign_polynomials(self, node: AccessTreeNode, s_i: List[object]) -> None:
        if node.type == "gate" and node.level_node_id is not None:
            index = int(node.level_node_id[1:]) - 1
            if index < len(s_i):
                node.q_x_0 = s_i[index]
            else:
                node.q_x_0 = self.group.random(ZR)
        elif node.parent is not None:
            node.q_x_0 = node.parent.q_x_0
        else:
            node.q_x_0 = s_i[0] if s_i else self.group.random(ZR)

        if node.type == "gate" and node.children:
            degree = node.threshold - 1
            coeffs = [node.q_x_0] + [self.group.random(ZR) for _ in range(degree)]
            for child in node.children:
                x = self.group.init(ZR, child.index + 1)
                child.q_x_0 = self._evaluate_polynomial(coeffs, x)
                self._assign_polynomials(child, s_i)

    def _evaluate_polynomial(self, coeffs: List[object], x: object) -> object:
        result = self.group.init(ZR, 0)
        for i, coeff in enumerate(coeffs):
            result += coeff * (x ** i)
        return result

    def _get_leaf_nodes(self, node: AccessTreeNode) -> List[AccessTreeNode]:
        leaves = []
        if node.type == "leaf":
            leaves.append(node)
        else:
            for child in node.children:
                leaves.extend(self._get_leaf_nodes(child))
        return leaves

    def transform(self, MPK: Dict, CT: Dict, TK: Dict, user_attributes: Set[str]) -> Optional[Dict]:
        access_tree = CT['access_tree']
        node_values = {}
        can_decrypt = self._evaluate_access_tree(access_tree, user_attributes, TK, CT, node_values)

        if not can_decrypt:
            logging.debug("Attributes do not satisfy access tree for transformation.")
            return None

        CT_trans = {}
        level_nodes = self._get_level_nodes(access_tree)
        if not level_nodes:
            level_nodes = [access_tree] * len(CT['encrypted_messages'])
            for i, node in enumerate(level_nodes):
                node.level_node_id = f"L{i+1}"

        for node in level_nodes:
            if node in node_values:
                node_id = node.level_node_id
                F_x = node_values[node]
                C_L_i = CT[f'C_{node_id}']
                C_prime_L_i = CT[f'C_prime_{node_id}']
                C_double_prime_L_i = CT[f'C_double_prime_{node_id}']
                C_triple_prime_L_i = CT[f'C_triple_prime_{node_id}']
                E_i = TK['E_i']
                E_i_prime = TK['E_i_prime']

                num = pair(C_prime_L_i, E_i)
                denom = pair(C_double_prime_L_i, E_i_prime)
                term = num / denom

                CT_trans[node_id] = {'C_L_i': C_L_i, 'term': term}

        CT_trans['encrypted_messages'] = CT['encrypted_messages']
        CT_trans['ck'] = CT['ck']
        return CT_trans

    def decrypt(self, MPK: Dict, CT: Dict, SK: Dict, user_attributes: Set[str]) -> List[str]:
        access_tree = CT['access_tree']
        encrypted_messages = CT['encrypted_messages']
        decrypted_messages = []

        node_values = {}
        can_decrypt = self._evaluate_access_tree(access_tree, user_attributes, SK, CT, node_values)

        if not can_decrypt:
            logging.debug("Attributes do not satisfy access tree.")
            return decrypted_messages

        level_nodes = self._get_level_nodes(access_tree)
        if not level_nodes:
            level_nodes = [access_tree] * len(encrypted_messages)
            for i, node in enumerate(level_nodes):
                node.level_node_id = f"L{i+1}"

        for node in level_nodes:
            if node in node_values:
                node_id = node.level_node_id
                F_x = node_values[node]
                C_L_i = CT[f'C_{node_id}']
                C_prime_L_i = CT[f'C_prime_{node_id}']
                C_double_prime_L_i = CT[f'C_double_prime_{node_id}']
                C_triple_prime_L_i = CT[f'C_triple_prime_{node_id}']
                E_i = SK['E_i']
                E_i_prime = SK['E_i_prime']

                num = pair(C_prime_L_i, E_i)
                denom = pair(C_double_prime_L_i, E_i_prime)
                term = num / denom

                ck_i = C_L_i / term
                ck_bytes = CT['ck'][int(node_id[1:]) - 1]
                iv, ct = encrypted_messages[int(node_id[1:]) - 1]
                cipher = AES.new(ck_bytes, AES.MODE_CBC, iv)
                try:
                    decrypted_msg = unpad(cipher.decrypt(ct), AES.block_size).decode()
                    decrypted_messages.append(decrypted_msg)
                except ValueError as e:
                    logging.error(f"Decryption failed for node {node_id}: {e}")

        return decrypted_messages

    def decrypt_out(self, CT_trans: Dict, RK: object) -> List[str]:
        decrypted_messages = []
        for node_id, components in CT_trans.items():
            if node_id.startswith('L'):
                C_L_i = components['C_L_i']
                term = components['term']
                ck_i = C_L_i / (term ** RK)
                ck_bytes = CT_trans['ck'][int(node_id[1:]) - 1]
                iv, ct = CT_trans['encrypted_messages'][int(node_id[1:]) - 1]
                cipher = AES.new(ck_bytes, AES.MODE_CBC, iv)
                try:
                    decrypted_msg = unpad(cipher.decrypt(ct), AES.block_size).decode()
                    decrypted_messages.append(decrypted_msg)
                except ValueError as e:
                    logging.error(f"Outsourced decryption failed for node {node_id}: {e}")

        return decrypted_messages

    def _evaluate_access_tree(self, node: AccessTreeNode, user_attributes: Set[str], SK: Dict, CT: Dict, node_values: Dict) -> bool:
        if node.type == "leaf":
            if node.attribute in user_attributes:
                C_x = CT.get(f'C_{node.attribute}')
                C_x_prime = CT.get(f'C_prime_{node.attribute}')
                D_i_j = SK.get(f'D_{node.attribute}')
                D_i_j_prime = SK.get(f'D_prime_{node.attribute}')
                if not all([C_x, C_x_prime, D_i_j, D_i_j_prime]):
                    logging.debug(f"Missing components for attribute {node.attribute}")
                    return False
                num = pair(C_x, D_i_j)
                denom = pair(C_x_prime, D_i_j_prime)
                node_values[node] = num / denom
                logging.debug(f"Leaf {node.attribute} satisfied")
                return True
            logging.debug(f"Leaf {node.attribute} not in user_attributes")
            return False
        else:
            child_values = []
            child_indices = []
            for child in node.children:
                if self._evaluate_access_tree(child, user_attributes, SK, CT, node_values):
                    child_values.append(node_values[child])
                    child_indices.append(child.index + 1)
            if len(child_values) >= node.threshold:
                s_x = self.group.init(GT, 1)
                for i, value in enumerate(child_values):
                    lagrange = self._lagrange_coefficient(child_indices, i, 0)
                    s_x *= value ** lagrange
                node_values[node] = s_x
                logging.debug(f"Gate satisfied with {len(child_values)}/{node.threshold} children")
                return True
            logging.debug(f"Gate not satisfied: {len(child_values)}/{node.threshold} children")
            return False

    def _lagrange_coefficient(self, indices: List[int], i: int, x: int) -> ZR:
        result = self.group.init(ZR, 1)
        x_i = indices[i]
        for j, x_j in enumerate(indices):
            if j != i:
                num = self.group.init(ZR, x - x_j)
                denom = self.group.init(ZR, x_i - x_j)
                result *= num / denom
        return result

    def _get_level_nodes(self, node: AccessTreeNode) -> List[AccessTreeNode]:
        level_nodes = []
        if node.type == "gate" and node.level_node_id is not None:
            level_nodes.append(node)
        for child in node.children:
            level_nodes.extend(self._get_level_nodes(child))
        return level_nodes

    def compute_sizes(self, MPK: Dict, MSK: Dict, SK: Dict, CT: Dict) -> Dict[str, int]:
        """Compute sizes of cryptographic components."""
        sizes = {}
        mpk_bytes = sum(len(self.group.serialize(value)) for value in MPK.values())
        sizes['MPK'] = mpk_bytes

        msk_bytes = sum(len(self.group.serialize(value)) for value in MSK.values())
        sizes['MSK'] = msk_bytes

        sk_bytes = sum(len(self.group.serialize(value)) for value in SK.values())
        sizes['SK'] = sk_bytes

        ct_bytes = 0
        for key, value in CT.items():
            if key == 'encrypted_messages':
                for iv, ct in value:
                    ct_bytes += len(iv) + len(ct)
            elif key == 'ck':
                for ck in value:
                    ct_bytes += len(ck)
            elif key == 'access_tree':
                def count_nodes(node):
                    count = 1
                    for child in node.children:
                        count += count_nodes(child)
                    return count
                node_count = count_nodes(value)
                ct_bytes += node_count * 100
            else:
                ct_bytes += len(self.group.serialize(value))
        sizes['CT'] = ct_bytes

        return sizes

def main():
    cpabe = CRFHCPABE()
    MPK, MSK = cpabe.setup()

    num_files = 2
    num_attrs = 6
    attributes = [f"attr{i+1}" for i in range(num_attrs)]
    access_tree = create_access_tree(num_attrs, attributes)
    messages = [f"File{i+1}" for i in range(num_files)]

    try:
        ciphertext = cpabe.encrypt(MPK, messages, access_tree)
    except ValueError as e:
        print(f"Encryption failed: {e}")
        return

    # User needs minimal attributes to satisfy the policy (e.g., attr1)
    user_attributes = {'attr1'}
    uid = "user1"
    private_key = cpabe.keygen(MPK, MSK, user_attributes, uid)
    decrypted_messages = cpabe.decrypt(MPK, ciphertext, private_key, user_attributes)
    print("Decrypted messages:", decrypted_messages)

if __name__ == '__main__':
    main()
