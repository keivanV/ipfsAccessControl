import asyncio
import json
from typing import Any, Dict, Optional
from dataclasses import dataclass

@dataclass
class ContractStub:
    """Stub for contract operations."""
    state: Dict[str, Any]

    def reset_state(self):
        """Reset the contract state."""
        self.state = {}

    def put_state(self, key: str, value: Any):
        """Store a key-value pair in the state."""
        self.state[key] = value

    def get_state(self, key: str) -> Any:
        """Retrieve a value by key from the state."""
        return self.state.get(key)

    def delete_state(self, key: str):
        """Delete a key-value pair from the state."""
        self.state.pop(key, None)

class HyperledgerFabric:
    """Interface for interacting with a Hyperledger Fabric network."""

    def __init__(self):
        self._gateway = None
        self._network = None
        self.stub = ContractStub(state={})

    async def connect_to_gateway(self, username: str, user_type: str) -> 'HyperledgerFabric':
        """Connect to the Hyperledger Fabric gateway.

        Args:
            username: The username for authentication.
            user_type: The type of user (e.g., 'owner', 'requester').

        Returns:
            HyperledgerFabric: The connected fabric instance.
        """
        print(f"Connecting to gateway as {username} ({user_type})...")
        # Simulate gateway connection
        self._gateway = {"username": username, "user_type": user_type}
        await asyncio.sleep(0.1)  # Simulate network latency
        return self

    async def get_network(self, channel_name: str) -> 'Network':
        """Get a network instance for the specified channel.

        Args:
            channel_name: The name of the channel.

        Returns:
            Network: The network instance.
        """
        if not self._gateway:
            raise ValueError("Gateway not connected. Call connect_to_gateway first.")
        print(f"Accessing network channel: {channel_name}")
        self._network = Network(channel_name, self.stub)
        return self._network

    async def close(self):
        """Close the gateway connection."""
        if self._gateway:
            print("Disconnecting from gateway...")
            self._gateway = None
            self._network = None
            await asyncio.sleep(0.1)  # Simulate disconnection latency

class Network:
    """Represents a Hyperledger Fabric network channel."""

    def __init__(self, channel_name: str, stub: ContractStub):
        self.channel_name = channel_name
        self.stub = stub

    def get_contract(self, chaincode_name: str) -> 'Contract':
        """Get a contract instance for the specified chaincode.

        Args:
            chaincode_name: The name of the chaincode.

        Returns:
            Contract: The contract instance.
        """
        print(f"Accessing chaincode: {chaincode_name} on channel: {self.channel_name}")
        return Contract(chaincode_name, self.stub)

class Contract:
    """Represents a smart contract on a Hyperledger Fabric network."""

    def __init__(self, chaincode_name: str, stub: ContractStub):
        self.chaincode_name = chaincode_name
        self.stub = stub

    async def submit_transaction(self, function_name: str, *args: Any) -> None:
        """Submit a transaction to the chaincode.

        Args:
            function_name: The name of the chaincode function to invoke.
            *args: Arguments to pass to the function.

        Raises:
            Exception: If the transaction fails.
        """
        print(f"Submitting transaction: {function_name} with args: {args}")
        await asyncio.sleep(0.1)  # Simulate transaction processing time

        # Simulate transaction logic
        if function_name == 'CreateUser':
            user_id, role, created_at, public_key, policy_set = args
            self.stub.put_state(f"user:{user_id}", {
                'id': user_id,
                'role': role,
                'createdAt': created_at,
                'publicKey': public_key,
                'policySet': json.loads(policy_set)
            })
        elif function_name == 'DeleteUser':
            user_id = args[0]
            self.stub.delete_state(f"user:{user_id}")
        elif function_name == 'CreateAsset':
            asset_id, meta_data, policy_set, public_key, created_at, updated_at, owner, name, cid, prev_cid, hash_access_key, fragments_map, hashed_attributes, promote_attributes = args
            self.stub.put_state(f"asset:{asset_id}", {
                'id': asset_id,
                'metaData': json.loads(meta_data),
                'policySet': json.loads(policy_set),
                'publicKey': public_key,
                'createdAt': created_at,
                'updatedAt': updated_at,
                'owner': owner,
                'name': name,
                'cid': cid,
                'prevCid': prev_cid,
                'hashAccessKey': hash_access_key,
                'fragmentsMap': json.loads(fragments_map),
                'hashedAttributes': json.loads(hashed_attributes),
                'promoteAttributes': json.loads(promote_attributes),
                'promotedAccess': [],
                'revokedAccess': [],
                'requesters': []
            })
        elif function_name == 'DeleteAsset':
            asset_id = args[0]
            self.stub.delete_state(f"asset:{asset_id}")
        elif function_name == 'UpdateAsset':
            asset_id, meta_data, policy_set, public_key, created_at, updated_at, owner, name, cid, prev_cid, hash_access_key, fragments_map, hashed_attributes, promote_attributes = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset.update({
                    'metaData': json.loads(meta_data),
                    'policySet': json.loads(policy_set),
                    'publicKey': public_key,
                    'updatedAt': updated_at,
                    'name': name,
                    'cid': cid,
                    'prevCid': prev_cid,
                    'hashAccessKey': hash_access_key,
                    'fragmentsMap': json.loads(fragments_map),
                    'hashedAttributes': json.loads(hashed_attributes),
                    'promoteAttributes': json.loads(promote_attributes)
                })
                self.stub.put_state(f"asset:{asset_id}", asset)
        elif function_name == 'PromoteAccess':
            user_id, asset_id, timestamp = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset['promotedAccess'].append({'username': user_id, 'timestamp': timestamp})
                self.stub.put_state(f"asset:{asset_id}", asset)
        elif function_name == 'DemoteAccess':
            user_id, asset_id, timestamp = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset['promotedAccess'] = [access for access in asset['promotedAccess'] if access['username'] != user_id]
                self.stub.put_state(f"asset:{asset_id}", asset)
        elif function_name == 'RevokePermanentAccess':
            user_id, asset_id, timestamp = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset['revokedAccess'].append({'username': user_id, 'timestamp': timestamp})
                self.stub.put_state(f"asset:{asset_id}", asset)
        elif function_name == 'GrantAccess':
            user_id, asset_id, timestamp = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset['requesters'].append({'username': user_id, 'timestamp': timestamp})
                self.stub.put_state(f"asset:{asset_id}", asset)
        elif function_name == 'RestoreAccess':
            user_id, asset_id, timestamp = args
            asset = self.stub.get_state(f"asset:{asset_id}")
            if asset:
                asset['revokedAccess'] = [access for access in asset['revokedAccess'] if access['username'] != user_id]
                self.stub.put_state(f"asset:{asset_id}", asset)
        else:
            print(f"Unknown function: {function_name}")

    async def evaluate_transaction(self, function_name: str, *args: Any) -> Optional[bytes]:
        """Evaluate a transaction (query) on the chaincode.

        Args:
            function_name: The name of the chaincode function to invoke.
            *args: Arguments to pass to the function.

        Returns:
            Optional[bytes]: The result of the query, encoded as bytes, or None if the query fails.
        """
        print(f"Evaluating transaction: {function_name} with args: {args}")
        await asyncio.sleep(0.05)  # Simulate query processing time

        # Simulate query logic
        if function_name == 'UserExists':
            user_id = args[0]
            exists = self.stub.get_state(f"user:{user_id}") is not None
            return json.dumps({'exists': exists}).encode('utf-8')
        elif function_name == 'GetUser':
            user_id = args[0]
            user = self.stub.get_state(f"user:{user_id}")
            return json.dumps(user).encode('utf-8') if user else b''
        elif function_name == 'AssetExists':
            asset_id = args[0]
            exists = self.stub.get_state(f"asset:{asset_id}") is not None
            return json.dumps({'exists': exists}).encode('utf-8')
        elif function_name == 'ReadAsset':
            asset_id = args[0]
            asset = self.stub.get_state(f"asset:{asset_id}")
            return json.dumps(asset).encode('utf-8') if asset else b''
        elif function_name == 'GetAssetsByOwnerAndName':
            owner, name, _ = args
            assets = [
                asset for key, asset in self.stub.state.items()
                if key.startswith('asset:') and asset.get('owner') == owner and asset.get('name') == name
            ]
            return json.dumps(assets).encode('utf-8')
        elif function_name == 'GetAllAssets':
            assets = [asset for key, asset in self.stub.state.items() if key.startswith('asset:')]
            return json.dumps(assets).encode('utf-8')
        elif function_name == 'CheckAccess':
            user_id, asset_id = args
            user = self.stub.get_state(f"user:{user_id}")
            asset = self.stub.get_state(f"asset:{asset_id}")
            if not user or not asset:
                return json.dumps({'access': False}).encode('utf-8')
            # Simulate access check logic
            user_policy = set(json.dumps(p, sort_keys=True) for p in user.get('policySet', []))
            asset_policy = set(json.dumps(p, sort_keys=True) for p in asset.get('policySet', []))
            access_granted = bool(user_policy & asset_policy)
            return json.dumps({'access': access_granted}).encode('utf-8')
        else:
            print(f"Unknown query function: {function_name}")
            return b''