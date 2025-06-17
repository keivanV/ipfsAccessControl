import json
import hashlib
import shamir
from typing import Dict, List, Any
from base64 import b64encode, b64decode
from datetime import datetime

class AssetTransferABAC:
    async def create_user(self, stub, username: str, role: str, created_at: str, public_key: str, policy_set: str) -> Dict:
        exists = await self.user_exists(stub, username)
        if exists:
            raise ValueError(f"User {username} already exists")

        user = {
            "Username": username,
            "Role": role,
            "CreatedAt": created_at,
            "PublicKey": public_key,
            "PolicySet": json.loads(policy_set)
        }

        await stub.put_state(username, json.dumps(self._sort_keys_recursive(user)).encode('utf-8'))
        return user

    async def hash_key_value_pairs(self, policy_attributes: List[Dict]) -> List[Dict]:
        hashed_attributes = []
        for attribute in policy_attributes:
            for key, value in attribute.items():
                concatenated = f"{key}:{json.dumps(value)}"
                combined_hash = hashlib.sha256(concatenated.encode('utf-8')).hexdigest()
                hashed_attributes.append({key: value, "hash": combined_hash})
        return hashed_attributes

    async def user_exists(self, stub, username: str) -> bool:
        user_json = await stub.get_state(username)
        return user_json is not None and len(user_json) > 0

    async def get_user(self, stub, username: str) -> str:
        user_json = await stub.get_state(username)
        if not user_json or len(user_json) == 0:
            raise ValueError(f"User {username} does not exist")
        return user_json.decode('utf-8')

    async def get_assets_by_owner_and_name(self, stub, owner: str, name: str, user_type: str) -> List[Dict]:
        try:
            results_iterator = await stub.get_state_by_range("", "")
            assets = []

            async for key, value in results_iterator:
                try:
                    str_value = value.decode('utf-8')
                    record = json.loads(str_value)
                    if record.get("owner") == owner and record.get("name") == name and record.get("userType") == user_type:
                        assets.append(record)
                except json.JSONDecodeError as err:
                    print(f"Error parsing asset at key {key}: {err}")
                except Exception as err:
                    print(f"Error processing asset at key {key}: {err}")
            return assets
        except Exception as err:
            raise ValueError(f"Failed to get assets: {str(err)}")

    async def asset_exists(self, stub, id: str) -> bool:
        asset_json = await stub.get_state(id)
        return asset_json is not None and len(asset_json) > 0

    async def delete_asset(self, stub, id: str) -> str:
        exists = await self.asset_exists(stub, id)
        if not exists:
            raise ValueError(f"The asset {id} does not exist")
        await stub.delete_state(id)
        return f"Asset {id} deleted successfully"

    async def create_asset(self, stub, id: str, meta_data: str, policy_set: str, public_key_owner: str, 
                          release_at: str, updated_at: str, owner: str, name: str, cid: str, prev_cid: str, 
                          hash_access_key: str, fragments_map: str, hashed_attributes: str, promote_attributes: str) -> Dict:
        exists = await self.asset_exists(stub, id)
        if exists:
            raise ValueError(f"The asset {id} already exists")

        asset = {
            "type": "DEMO",
            "ID": id,
            "MetaData": meta_data,
            "policySet": json.loads(policy_set),
            "publicKeyOwner": public_key_owner,
            "ReleasedAt": release_at,
            "UpdatedAt": updated_at,
            "Requesters": [],
            "revokedAccess": [],
            "promotedAccess": [],
            "owner": owner,
            "name": name,
            "cid": cid,
            "PrevCid": prev_cid,
            "hashAccessKey": hash_access_key,
            "fragmentsMap": json.loads(fragments_map),
            "hashedAttributes": json.loads(hashed_attributes),
            "promoteAttributes": json.loads(promote_attributes)
        }

        await stub.put_state(id, json.dumps(self._sort_keys_recursive(asset)).encode('utf-8'))
        return asset

    async def read_asset(self, stub, id: str) -> str:
        asset_json = await stub.get_state(id)
        if not asset_json or len(asset_json) == 0:
            raise ValueError(f"The asset {id} does not exist")
        return asset_json.decode('utf-8')

    async def update_asset(self, stub, id: str, meta_data: str, policy_set: str, public_key_owner: str, 
                          release_at: str, updated_at: str, owner: str, name: str, cid: str, prev_cid: str, 
                          hash_access_key: str, fragments_map: str, hashed_attributes: str, promote_attributes: str) -> Dict:
        exists = await self.asset_exists(stub, id)
        if not exists:
            raise ValueError(f"The asset {id} does not exist")

        asset_string = await self.read_asset(stub, id)
        existing_asset = json.loads(asset_string)

        try:
            parsed_promote_attributes = json.loads(promote_attributes) if isinstance(promote_attributes, str) else promote_attributes
            if not isinstance(parsed_promote_attributes, list):
                parsed_promote_attributes = [parsed_promote_attributes]
            parsed_promote_attributes = [
                attr for attr in parsed_promote_attributes
                if (isinstance(attr.get("interest"), list) and len(attr.get("interest", [])) > 0) or
                   (isinstance(attr.get("languages"), list) and len(attr.get("languages", [])) > 0)
            ]
            if not parsed_promote_attributes:
                raise ValueError("promoteAttributes must contain at least one valid policy")
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid promoteAttributes format: {str(error)}")

        parsed_policy_set = json.loads(policy_set) if isinstance(policy_set, str) else policy_set
        parsed_fragments_map = json.loads(fragments_map) if isinstance(fragments_map, str) else fragments_map
        parsed_hashed_attributes = json.loads(hashed_attributes) if isinstance(hashed_attributes, str) else hashed_attributes

        updated_asset = {
            "type": "DEMO",
            "ID": id,
            "MetaData": meta_data,
            "policySet": parsed_policy_set,
            "publicKeyOwner": public_key_owner,
            "ReleasedAt": release_at,
            "UpdatedAt": updated_at,
            "Requesters": existing_asset.get("Requesters", []),
            "revokedAccess": existing_asset.get("revokedAccess", []),
            "promotedAccess": existing_asset.get("promotedAccess", []),
            "owner": owner,
            "name": name,
            "cid": cid,
            "PrevCid": prev_cid,
            "hashAccessKey": hash_access_key,
            "fragmentsMap": parsed_fragments_map,
            "hashedAttributes": parsed_hashed_attributes,
            "promoteAttributes": parsed_promote_attributes
        }

        await stub.put_state(id, json.dumps(self._sort_keys_recursive(updated_asset)).encode('utf-8'))
        return updated_asset

    async def revoke_permanent_access(self, stub, username: str, asset_id: str, revoked_at: str) -> Dict:
        asset_string = await self.read_asset(stub, asset_id)
        if not asset_string:
            raise ValueError(f"Asset with ID {asset_id} not found.")

        asset = json.loads(asset_string)
        if "revokedAccess" not in asset:
            asset["revokedAccess"] = []

        asset["revokedAccess"].append({
            "username": username,
            "type": "permanent",
            "revokedAt": revoked_at
        })

        await stub.put_state(asset_id, json.dumps(self._sort_keys_recursive(asset)).encode('utf-8'))
        return asset

    async def restore_access(self, stub, username: str, asset_id: str, restored_at: str) -> Dict:
        asset_string = await self.read_asset(stub, asset_id)
        if not asset_string:
            raise ValueError(f"Asset with ID {asset_id} not found.")

        asset = json.loads(asset_string)
        if not asset.get("revokedAccess"):
            raise ValueError(f"No revoked access found for asset {asset_id}")

        initial_length = len(asset["revokedAccess"])
        asset["revokedAccess"] = [
            access for access in asset["revokedAccess"]
            if not (access["username"] == username and access["type"] == "permanent")
        ]

        if len(asset["revokedAccess"]) == initial_length:
            raise ValueError(f"User {username} was not permanently revoked for asset {asset_id}")

        if "accessHistory" not in asset:
            asset["accessHistory"] = []
        asset["accessHistory"].append({
            "username": username,
            "action": "restored",
            "restoredAt": restored_at
        })

        await stub.put_state(asset_id, json.dumps(self._sort_keys_recursive(asset)).encode('utf-8'))
        return asset

    async def promote_access(self, stub, username: str, asset_id: str, promoted_at: str) -> Dict:
        print(f"[PromoteAccess] Processing for user {username}, asset {asset_id}")
        user_string = await self.get_user(stub, username)
        if not user_string:
            raise ValueError(f"User {username} does not exist")
        user = json.loads(user_string)
        user_policy_set = user["PolicySet"]

        asset_string = await self.read_asset(stub, asset_id)
        if not asset_string:
            raise ValueError(f"Asset with ID {asset_id} not found")
        asset = json.loads(asset_string)
        print(f"[PromoteAccess] Initial asset state: {json.dumps(asset)}")

        if not asset.get("promoteAttributes"):
            raise ValueError(f"Asset {asset_id} has no promoteAttributes defined")
        promote_attributes = asset["promoteAttributes"] if isinstance(asset["promoteAttributes"], list) else json.loads(asset["promoteAttributes"])
        print(f"[PromoteAccess] promoteAttributes: {json.dumps(promote_attributes)}")
        print(f"[PromoteAccess] userPolicySet: {json.dumps(user_policy_set)}")

        has_matching_attributes = all(
            all(
                user_interest in user_policy["interest"] for user_interest in (attr.get("interest", []) if isinstance(attr.get("interest"), list) else [])
            ) and all(
                user_lang in user_policy["languages"] for user_lang in (attr.get("languages", []) if isinstance(attr.get("languages"), list) else [])
            )
            for attr in promote_attributes
            for user_policy in user_policy_set
        )

        if not has_matching_attributes:
            raise ValueError(f"User {username} does not have required attributes to be promoted for asset {asset_id}")

        if not asset.get("promotedAccess"):
            asset["promotedAccess"] = []
        if any(access["username"] == username for access in asset["promotedAccess"]):
            raise ValueError(f"User {username} already has promoted access for asset {asset_id}")

        asset["promotedAccess"].append({"username": username, "promotedAt": promoted_at})
        print(f"[PromoteAccess] Updated asset.promotedAccess: {json.dumps(asset['promotedAccess'])}")
        serialized_asset = json.dumps(self._sort_keys_recursive(asset)).encode('utf-8')
        print(f"[PromoteAccess] Serializing asset: {serialized_asset.decode('utf-8')}")
        await stub.put_state(asset_id, serialized_asset)
        print(f"[PromoteAccess] State updated for asset {asset_id}")
        return asset

    async def demote_access(self, stub, username: str, asset_id: str, demoted_at: str) -> Dict:
        print(f"[DemoteAccess] Processing for user {username}, asset {asset_id}")
        asset_string = await self.read_asset(stub, asset_id)
        if not asset_string:
            raise ValueError(f"Asset with ID {asset_id} not found.")
        asset = json.loads(asset_string)
        print(f"[DemoteAccess] Initial asset state: {json.dumps(asset)}")

        if not asset.get("promotedAccess"):
            asset["promotedAccess"] = []
        initial_length = len(asset["promotedAccess"])
        asset["promotedAccess"] = [access for access in asset["promotedAccess"] if access["username"] != username]
        print(f"[DemoteAccess] Updated promotedAccess: {json.dumps(asset['promotedAccess'])}")
        if len(asset["promotedAccess"]) == initial_length and initial_length > 0:
            raise ValueError(f"User {username} was not found in promoted access for asset {asset_id}")
        serialized_asset = json.dumps(self._sort_keys_recursive(asset)).encode('utf-8')
        print(f"[DemoteAccess] Serializing asset: {serialized_asset.decode('utf-8')}")
        await stub.put_state(asset_id, serialized_asset)
        print(f"[DemoteAccess] State updated for asset {asset_id}")
        return asset

    async def check_access(self, stub, username: str, asset_id: str) -> Dict:
        user = json.loads(await self.get_user(stub, username))
        try:
            user_policy_set = (
                json.loads(user["PolicySet"]) if isinstance(user["PolicySet"], str) else
                user["PolicySet"] if isinstance(user["PolicySet"], list) else
                [user["PolicySet"]] if isinstance(user["PolicySet"], dict) else
                None
            )
            if not isinstance(user_policy_set, list):
                raise ValueError("PolicySet should be an array")
        except Exception as error:
            print(f"Invalid PolicySet format for user {username}: {user['PolicySet']}")
            raise ValueError(f"Invalid JSON format for PolicySet of user {username}: {str(error)}")

        asset_json = await stub.get_state(asset_id)
        if not asset_json or len(asset_json) == 0:
            raise ValueError(f"Asset {asset_id} does not exist")
        asset = json.loads(asset_json.decode('utf-8'))
        if isinstance(asset["policySet"], str):
            asset["policySet"] = json.loads(asset["policySet"])

        is_permanent_revoked = asset.get("revokedAccess") and any(
            access["username"] == username and access["type"] == "permanent"
            for access in asset["revokedAccess"]
        )
        if is_permanent_revoked:
            return {"access": False}

        all_assets = await self.get_all_assets(stub)
        is_blocked_by_owner = any(
            record["owner"] == asset["owner"] and record.get("revokedAccess") and any(
                access["username"] == username and access["type"] == "permanent"
                for access in record["revokedAccess"]
            )
            for record in all_assets
        )
        if is_blocked_by_owner:
            return {"access": False}

        user_has_access = all(
            any(
                all(
                    all(value in user_policy.get(key, []) for value in asset_policy[key])
                    for key in asset_policy
                    if isinstance(user_policy.get(key), list)
                )
                for user_policy in user_policy_set
            )
            for asset_policy in asset["policySet"]
        )

        if not user_has_access:
            return {"access": False}

        extracted_shares = {}
        for index, fragment in enumerate(asset["fragmentsMap"][:len(asset["hashedAttributes"])]):
            extracted_shares[index + 1] = fragment["share"]
        
        result = {k: bytes(v) for k, v in extracted_shares.items()}
        recovered = shamir.join(result)
        recovered_access_key = recovered.decode('utf-8')
        return {"access": True, "owner": asset["owner"], "key": recovered_access_key}

    async def grant_access(self, stub, username: str, asset_id: str, granted_at: str) -> Dict:
        asset_string = await self.read_asset(stub, asset_id)
        asset = json.loads(asset_string)
        asset["Requesters"].append({"username": username, "grantedAt": granted_at})
        await stub.put_state(asset_id, json.dumps(self._sort_keys_recursive(asset)).encode('utf-8'))
        return asset

    async def delete_user(self, stub, username: str) -> str:
        exists = await self.user_exists(stub, username)
        if not exists:
            raise ValueError(f"User {username} does not exist")
        await stub.delete_state(username)
        return f"User {username} deleted successfully"

    async def delete_asset_public(self, stub, id: str) -> str:
        exists = await self.asset_exists(stub, id)
        if not exists:
            raise ValueError(f"The asset {id} does not exist")
        await stub.delete_state(id)
        return f"Asset {id} deleted successfully"

    async def transfer_asset(self, stub, id: str, new_public_key_owner: str) -> str:
        asset_string = await self.read_asset(stub, id)
        asset = json.loads(asset_string)
        old_owner = asset["publicKeyOwner"]
        asset["publicKeyOwner"] = new_public_key_owner
        asset["UpdatedAt"] = datetime.now().isoformat()
        await stub.put_state(id, json.dumps(self._sort_keys_recursive(asset)).encode('utf-8'))
        return old_owner

    async def get_all_assets(self, stub) -> List[Dict]:
        try:
            results_iterator = await stub.get_state_by_range("", "")
            all_results = []
            async for key, value in results_iterator:
                try:
                    str_value = value.decode('utf-8')
                    record = json.loads(str_value)
                    all_results.append(record)
                except json.JSONDecodeError as err:
                    print(f"Error parsing asset at key {key}: {err}")
                except Exception as err:
                    print(f"Error processing asset at key {key}: {err}")
            return all_results
        except Exception as err:
            raise ValueError(f"Failed to get assets: {str(err)}")

    async def get_asset_history(self, stub, id: str) -> List[Dict]:
        history = []
        iterator = await stub.get_history_for_key(id)
        while True:
            result = await iterator.next()
            if result["done"]:
                await iterator.close()
                break
            tx = {
                "txId": result["value"]["txId"],
                "timestamp": datetime.fromtimestamp(result["value"]["timestamp"]).isoformat(),
                "isDelete": result["value"]["isDelete"],
                "value": result["value"]["value"].decode('utf-8') if result["value"]["value"] else None,
            }
            try:
                if tx["value"]:
                    tx["value"] = json.loads(tx["value"])
            except json.JSONDecodeError:
                print(f"Non-JSON value in history: {tx['value']}")
            history.append(tx)
        return history

    def _sort_keys_recursive(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._sort_keys_recursive(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [self._sort_keys_recursive(item) for item in obj]
        return obj