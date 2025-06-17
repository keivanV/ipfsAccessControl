
import os
import json
import hashlib
import asyncio
import random
import csv
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from pyshamir import split, combine
from base64 import b64encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hyperledger import HyperledgerFabric

# Configuration
CHANNEL_NAME = 'sipfs'
CHAINCODE_NAME = 'basic'
USERNAME = 'test'
DELAY_MS = 0.1  # Converted to seconds for asyncio.sleep

# Utility functions
def generate_random_access_key(length: int = 16) -> str:
    return os.urandom(length).hex()

def hash_key_value_pairs(policy_attributes: List[Dict]) -> List[Dict]:
    hashed_attributes = []
    for attribute in policy_attributes:
        for key, value in attribute.items():
            concatenated = f"{key}:{json.dumps(value)}"
            combined_hash = hashlib.sha256(concatenated.encode('utf-8')).hexdigest()
            hashed_attributes.append({key: value, "hash": combined_hash})
    return hashed_attributes

async def save_results_to_csv(results: Dict, benchmark_name: str, iterations: str):
    headers = []
    records = []

    if benchmark_name == 'create_asset':
        headers = [
            {'id': 'runs', 'title': 'Runs'},
            {'id': 'avgLatency', 'title': 'Average Latency (ms)'},
            {'id': 'successfulRuns', 'title': 'Successful Runs'},
            {'id': 'totalRuns', 'title': 'Total Runs'}
        ]
        records = [{
            'runs': results['results']['runs'],
            'avgLatency': results['results']['avgLatency'],
            'successfulRuns': results['results']['successfulRuns'],
            'totalRuns': results['results']['totalRuns']
        }]
    elif benchmark_name == 'api_and_query':
        headers = [
            {'id': 'type', 'title': 'Type'},
            {'id': 'functionOrConcurrency', 'title': 'Function/Concurrency'},
            {'id': 'avgLatency', 'title': 'Average Latency (ms)'},
            {'id': 'successfulRunsOrTPS', 'title': 'Successful Runs/TPS'},
            {'id': 'totalRunsOrMetric', 'title': 'Total Runs/Metric'}
        ]
        records = [
            {
                'type': 'API Call',
                'functionOrConcurrency': r['function'],
                'avgLatency': r['avgLatency'],
                'successfulRunsOrTPS': r['successfulRuns'],
                'totalRunsOrMetric': r['totalRuns']
            } for r in results['results']['apiCalls']
        ] + [
            {
                'type': 'Query Latency',
                'functionOrConcurrency': r['concurrency'],
                'avgLatency': r['readAssetAvgLatency'],
                'successfulRunsOrTPS': r['readAssetTPS'],
                'totalRunsOrMetric': 'ReadAsset'
            } for r in results['results']['queryLatency']
        ] + [
            {
                'type': 'Query Latency',
                'functionOrConcurrency': r['concurrency'],
                'avgLatency': r['getAssetsByOwnerAndNameAvgLatency'],
                'successfulRunsOrTPS': r['getAssetsByOwnerAndNameTPS'],
                'totalRunsOrMetric': 'GetAssetsByOwnerAndName'
            } for r in results['results']['queryLatency']
        ]
    elif benchmark_name == 'promotion_check_by_attribute_count':
        headers = [
            {'id': 'attributeCount', 'title': 'Attribute Count'},
            {'id': 'avgLatency', 'title': 'Average Latency (ms)'},
            {'id': 'successfulRuns', 'title': 'Successful Runs'},
            {'id': 'totalRuns', 'title': 'Total Runs'},
            {'id': 'accessGrantedCount', 'title': 'Access Granted Count'},
            {'id': 'accessGrantedRate', 'title': 'Access Achievements'}
        ]
        records = [
            {
                'attributeCount': r['attributeCount'],
                'avgLatency': r['avgLatency'],
                'successfulRuns': r['successfulRuns'],
                'totalRuns': r['totalRuns'],
                'accessGrantedCount': r['accessGrantedCount'],
                'accessGrantedRate': r['accessGrantedRate']
            } for r in results['results']
        ]
    elif benchmark_name == 'promote_demote':
        headers = [
            {'id': 'function', 'title': 'Function'},
            {'id': 'description', 'title': 'Description'},
            {'id': 'avgLatency', 'title': 'Average Latency (ms)'},
            {'id': 'successfulRuns', 'title': 'Successful Runs'},
            {'id': 'totalRuns', 'title': 'Total Runs'}
        ]
        records = [
            {
                'function': r['function'],
                'description': r.get('description', ''),
                'avgLatency': r['avgLatency'],
                'successfulRuns': r['successfulRuns'],
                'totalRuns': r['totalRuns']
            } for r in results['results']
        ]
    elif benchmark_name == 'least_privilege':
        headers = [
            {'id': 'test', 'title': 'Test'},
            {'id': 'status', 'title': 'Status'},
            {'id': 'description', 'title': 'Description'},
            {'id': 'error', 'title': 'Error'}
        ]
        records = [
            {
                'test': r['test'],
                'status': r['status'],
                'description': r['description'],
                'error': r.get('error', '')
            } for r in results['results']
        ]

    if not headers or not records:
        print(f"No data to write to CSV for {benchmark_name}")
        return

    output_file = Path(f"{benchmark_name}_avg_{iterations}.csv")
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[h['id'] for h in headers])
        writer.writeheader()
        writer.writerows(records)
    print(f"Saved CSV results for {benchmark_name} to {output_file}")

async def run_benchmark_with_iterations(benchmark_fn, iteration_counts: List[int], benchmark_name: str) -> Dict:
    all_results = {}
    for iterations in iteration_counts:
        print(f"Running {benchmark_name} for {iterations} iterations...")
        iteration_results = []
        failed_runs = 0

        for i in range(iterations):
            print(f"Iteration {i + 1}/{iterations}")
            try:
                result = await benchmark_fn()
                iteration_results.append(result)
            except Exception as error:
                print(f"Error in {benchmark_name} iteration {i + 1}: {str(error)}")
                failed_runs += 1
            await asyncio.sleep(DELAY_MS)

        averaged_result = aggregate_results(iteration_results, iterations, failed_runs)
        all_results[f"{iterations}_iterations"] = averaged_result

        output_file = Path(f"{benchmark_name}_avg_{iterations}.json")
        with open(output_file, 'w') as f:
            json.dump(averaged_result, f, indent=2)
        print(f"Saved JSON results for {iterations} iterations to {output_file}")

        await save_results_to_csv(averaged_result, benchmark_name, str(iterations))

    combined_output_file = Path(f"{benchmark_name}_avg_all.json")
    with open(combined_output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"Saved combined JSON results to {combined_output_file}")

    for iterations in all_results:
        await save_results_to_csv(all_results[iterations], benchmark_name, iterations.replace('_iterations', ''))

    return all_results

def aggregate_results(results: List[Any], total_iterations: int, failed_runs: int) -> Dict:
    if not results:
        return {
            'iterations': total_iterations,
            'successfulIterations': 0,
            'failedIterations': failed_runs,
            'results': {'apiCalls': [], 'queryLatency': []}
        }

    if not isinstance(results[0], list):
        valid_results = [r for r in results if r.get('avgLatency', -1) >= 0]
        successful_runs = sum(r['successfulRuns'] for r in valid_results) / len(valid_results) if valid_results else 0
        total_runs = sum(r['totalRuns'] for r in valid_results) / len(valid_results) if valid_results else 0
        avg_latency = sum(float(r['avgLatency']) for r in valid_results) / len(valid_results) if valid_results else -1

        return {
            'iterations': total_iterations,
            'successfulIterations': len(valid_results),
            'failedIterations': failed_runs,
            'results': {
                'avgLatency': round(avg_latency, 3) if avg_latency >= 0 else -1,
                'latencyUnit': 'milliseconds',
                'successfulRuns': round(successful_runs),
                'totalRuns': round(total_runs)
            }
        }

    is_api_and_query = 'apiCalls' in results[0] and 'queryLatency' in results[0]
    if is_api_and_query:
        api_calls_aggregated = [
            {
                **template,
                'avgLatency': round(sum(float(item['avgLatency']) for r in results for item in r['apiCalls'] if item['function'] == template['function']) / len([item for r in results for item in r['apiCalls'] if item['function'] == template['function']]), 3) if any(item['function'] == template['function'] for r in results for item in r['apiCalls']) else -1,
                'successfulRuns': round(sum(item['successfulRuns'] for r in results for item in r['apiCalls'] if item['function'] == template['function']) / len([item for r in results for item in r['apiCalls'] if item['function'] == template['function']])),
                'totalRuns': round(sum(item['totalRuns'] for r in results for item in r['apiCalls'] if item['function'] == template['function']) / len([item for r in results for item in r['apiCalls'] if item['function'] == template['function']]))
            }
            for template in results[0]['apiCalls']
        ]

        query_aggregated = [
            {
                **template,
                'readAssetAvgLatency': round(sum(float(item['readAssetAvgLatency']) for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']) / len([item for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']]), 3) if any(item['concurrency'] == template['concurrency'] for r in results for item in r['queryLatency']) else -1,
                'readAssetTPS': round(sum(float(item['readAssetTPS']) for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']) / len([item for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']]), 2) if any(item['concurrency'] == template['concurrency'] for r in results for item in r['queryLatency']) else -1,
                'getAssetsByOwnerAndNameAvgLatency': round(sum(float(item['getAssetsByOwnerAndNameAvgLatency']) for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']) / len([item for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']]), 3) if any(item['concurrency'] == template['concurrency'] for r in results for item in r['queryLatency']) else -1,
                'getAssetsByOwnerAndNameTPS': round(sum(float(item['getAssetsByOwnerAndNameTPS']) for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']) / len([item for r in results for item in r['queryLatency'] if item['concurrency'] == template['concurrency']]), 2) if any(item['concurrency'] == template['concurrency'] for r in results for item in r['queryLatency']) else -1
            }
            for template in results[0]['queryLatency']
        ]

        return {
            'iterations': total_iterations,
            'successfulIterations': len(results),
            'failedIterations': failed_runs,
            'results': {
                'apiCalls': api_calls_aggregated,
                'queryLatency': query_aggregated
            }
        }

    is_promotion_check = results[0][0].get('attributeCount') is not None
    if is_promotion_check:
        aggregated = [
            {
                **template,
                'avgLatency': round(sum(float(item['avgLatency']) for r in results for item in r if item['attributeCount'] == template['attributeCount']) / len([item for r in results for item in r if item['attributeCount'] == template['attributeCount']]), 3) if any(item['attributeCount'] == template['attributeCount'] for r in results for item in r) else -1,
                'successfulRuns': round(sum(item['successfulRuns'] for r in results for item in r if item['attributeCount'] == template['attributeCount']) / len([item for r in results for item in r if item['attributeCount'] == template['attributeCount']])),
                'totalRuns': round(sum(item['totalRuns'] for r in results for item in r if item['attributeCount'] == template['attributeCount']) / len([item for r in results for item in r if item['attributeCount'] == template['attributeCount']])),
                'accessGrantedCount': round(sum(item['accessGrantedCount'] for r in results for item in r if item['attributeCount'] == template['attributeCount']) / len([item for r in results for item in r if item['attributeCount'] == template['attributeCount']])),
                'accessGrantedRate': round(sum(item['accessGrantedCount'] / item['successfulRuns'] for r in results for item in r if item['attributeCount'] == template['attributeCount'] and item['successfulRuns'] > 0) / len([item for r in results for item in r if item['attributeCount'] == template['attributeCount']]), 3) if any(item['attributeCount'] == template['attributeCount'] for r in results for item in r) else 0
            }
            for template in results[0]
        ]

        return {
            'iterations': total_iterations,
            'successfulIterations': len(results),
            'failedIterations': failed_runs,
            'results': aggregated
        }

    aggregated = [
        {
            **template,
            'avgLatency': round(sum(float(item['avgLatency']) for r in results for item in r if item['function'] == template['function']) / len([item for r in results for item in r if item['function'] == template['function']]), 3) if any(item['function'] == template['function'] for r in results for item in r) else -1,
            'successfulRuns': round(sum(item['successfulRuns'] for r in results for item in r if item['function'] == template['function']) / len([item for r in results for item in r if item['function'] == template['function']])),
            'totalRuns': round(sum(item['totalRuns'] for r in results for item in r if item['function'] == template['function']) / len([item for r in results for item in r if item['function'] == template['function']]))
        }
        for template in results[0]
    ]

    return {
        'iterations': total_iterations,
        'successfulIterations': len(results),
        'failedIterations': failed_runs,
        'results': aggregated
    }

def encrypt(text: str, symmetric_key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_text = text + ' ' * (16 - len(text) % 16)  # PKCS5-like padding
    encrypted = encryptor.update(padded_text.encode('utf-8')) + encryptor.finalize()
    return f"{iv.hex()}:{encrypted.hex()}"

def decrypt(encrypted_text: str, symmetric_key: bytes) -> str:
    iv, encrypted_data = encrypted_text.split(':')
    iv = bytes.fromhex(iv)
    encrypted_data = bytes.fromhex(encrypted_data)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted.rstrip().decode('utf-8')

def generate_unique_id(prefix: str) -> str:
    return f"{prefix}-{int(datetime.now().timestamp() * 1000)}-{os.urandom(4).hex()}"

# Attribute pools
ATTRIBUTE_POOLS = {
    'department': ['engineering', 'finance', 'hr', 'marketing', 'sales', 'it', 'research', 'operations', 'legal', 'support', 'qa', 'product', 'logistics', 'training', 'compliance'],
    'role': ['developer', 'manager', 'analyst', 'designer', 'engineer', 'consultant', 'admin', 'director', 'specialist', 'coordinator', 'architect', 'tester', 'scientist', 'executive', 'trainer'],
    'location': ['us', 'eu', 'asia', 'africa', 'australia', 'south_america', 'canada', 'middle_east', 'india', 'japan', 'china', 'brazil', 'uk', 'germany', 'france'],
    'skills': ['python', 'java', 'sql', 'javascript', 'cloud', 'devops', 'ai', 'blockchain', 'cybersecurity', 'data_analysis', 'ml', 'networking', 'machine_learning', 'ui_ux', 'big_data', 'embedded'],
    'clearance': ['public', 'confidential', 'secret', 'top_secret', 'restricted', 'classified', 'sensitive', 'internal', 'external', 'executive'],
    'languages': ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko', 'ar', 'hi', 'bn', 'sw', 'nl'],
    'interest': ['tech', 'finance', 'health', 'education', 'sports', 'music', 'art', 'science', 'travel', 'gaming', 'environment', 'politics', 'fashion', 'food', 'literature']
}

def get_random_subset(array: List[str], n: int) -> List[str]:
    return random.sample(array, min(n, len(array)))

def generate_random_policy_attribute() -> Dict:
    num_keys = random.randint(5, 7)
    available_keys = list(ATTRIBUTE_POOLS.keys())
    selected_keys = get_random_subset(available_keys, num_keys)
    attribute = {}
    for key in selected_keys:
        num_values = random.randint(5, 10)
        attribute[key] = get_random_subset(ATTRIBUTE_POOLS[key], num_values)
    return attribute

def generate_user_policy_set(attribute_count: int, include_required: bool = False, required_policies: List[Dict] = None) -> str:
    attributes = []
    required_policy_options = required_policies or [{
        'department': ['engineering'],
        'role': ['developer'],
        'skills': ['python'],
        'clearance': ['confidential'],
        'location': ['us'],
        'languages': ['en'],
        'interest': ['tech']
    }]

    if include_required and required_policy_options:
        attributes.append(random.choice(required_policy_options))

    for _ in range(len(attributes), attribute_count):
        attributes.append(generate_random_policy_attribute())

    return json.dumps(sorted(attributes, key=lambda x: json.dumps(x)))

def generate_shamir_fragments(secret: str, parts: int, quorum: int) -> Dict:
    secret_bytes = secret.encode('utf-8')
    try:
        shares = split(secret_bytes, parts, quorum)  # pyshamir.split returns list of bytearrays
    except Exception as e:
        raise ValueError(f"Failed to generate Shamir shares: {str(e)}")
    policy_attributes = [
        {'interest': [f'topic{i + 1}'], 'languages': ['en']}
        for i in range(parts)
    ]
    hashed_attributes = hash_key_value_pairs(policy_attributes)
    fragments_map = [
        {**attr, 'share': share.hex()}  # Convert bytearray to hex string
        for i, (attr, share) in enumerate(zip(hashed_attributes[:parts], shares))
    ]
    return {'fragments_map': fragments_map, 'hashedAttributes': hashed_attributes}

async def connect_to_user_gateway(username: str, user_type: str):
    fabric = HyperledgerFabric()
    return await fabric.connect_to_gateway(username, user_type)

async def setup_test_data(contract) -> Dict:
    print('Setting up test data for benchmarks...')
    asset_id = generate_unique_id('asset')
    user_id = generate_unique_id('user')
    current_date = datetime.now().isoformat()

    try:
        contract.stub.reset_state()
        print(f"State reset for asset {asset_id} and user {user_id}")

        owner_exists = False
        try:
            owner_exists_result = await contract.evaluate_transaction('UserExists', USERNAME)
            if owner_exists_result:
                owner_exists = json.loads(owner_exists_result.decode('utf-8')).get('exists', False)
                if owner_exists:
                    owner_result = await contract.evaluate_transaction('GetUser', USERNAME)
                    if not owner_result or len(owner_result) == 0:
                        print(f"Owner user {USERNAME} exists but has invalid state, recreating...")
                        owner_exists = False
        except Exception as error:
            print(f"Owner user {USERNAME} does not exist, will create: {str(error)}")
            owner_exists = False

        if not owner_exists:
            policy_set = generate_user_policy_set(1, True)
            await contract.submit_transaction(
                'CreateUser',
                USERNAME,
                'owner',
                current_date,
                'dummy-public-key',
                policy_set
            )
            print(f"Owner user {USERNAME} created successfully")
        else:
            print(f"Owner user {USERNAME} already exists, skipping creation")

        user_exists = False
        try:
            user_exists_result = await contract.evaluate_transaction('UserExists', user_id)
            if user_exists_result:
                user_exists = json.loads(user_exists_result.decode('utf-8')).get('exists', False)
                if user_exists:
                    user_result = await contract.evaluate_transaction('GetUser', user_id)
                    if not user_result or len(user_result) == 0:
                        print(f"User {user_id} exists but has invalid state, recreating...")
                        user_exists = False
        except Exception as error:
            print(f"User {user_id} does not exist, will create: {str(error)}")
            user_exists = False

        if not user_exists:
            policy_set = generate_user_policy_set(1, True, [{'interest': ['tech'], 'languages': ['en']}])
            await contract.submit_transaction(
                'CreateUser',
                user_id,
                'requester',
                current_date,
                'dummy-public-key',
                policy_set
            )
            print(f"User {user_id} created successfully with matching policy")
        else:
            print(f"User {user_id} already exists, skipping creation")

        asset_exists = False
        try:
            asset_exists_result = await contract.evaluate_transaction('AssetExists', asset_id)
            if asset_exists_result:
                asset_exists = json.loads(asset_exists_result.decode('utf-8')).get('exists', False)
        except Exception as error:
            print(f"Error checking if asset {asset_id} exists: {str(error)}")
            asset_exists = False

        if asset_exists:
            print(f"Asset {asset_id} already exists, deleting...")
            try:
                await contract.submit_transaction('DeleteAsset', asset_id)
                print(f"Asset {asset_id} deleted successfully")
            except Exception as error:
                print(f"Error deleting asset {asset_id}: {str(error)}")

        meta_data = json.dumps({'description': 'Test asset'})
        policy_set = json.dumps([{'interest': ['tech'], 'languages': ['en']}])
        promote_attributes = json.dumps([{'interest': ['tech'], 'languages': ['en']}])
        public_key_owner = 'pubkey123'
        name = 'TestAsset'
        cid = 'cid123'
        prev_cid = ''
        key = generate_random_access_key()
        hash_access_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
        fragments = generate_shamir_fragments(key, 2, 2)

        await contract.submit_transaction(
            'CreateAsset',
            asset_id,
            meta_data,
            policy_set,
            public_key_owner,
            current_date,
            current_date,
            USERNAME,
            name,
            cid,
            prev_cid,
            hash_access_key,
            json.dumps(fragments['fragments_map']),
            json.dumps(fragments['hashedAttributes']),
            promote_attributes
        )
        print(f"Asset {asset_id} created successfully")

        return {'userId': user_id, 'assetId': asset_id, 'owner': USERNAME}
    except Exception as error:
        print(f"Error in setup_test_data: {str(error)}")
        raise

async def cleanup_test_data(contract, asset_id: str = None, user_id: str = None):
    try:
        if asset_id and contract:
            try:
                exists_result = await contract.evaluate_transaction('AssetExists', asset_id)
                if exists_result and json.loads(exists_result.decode('utf-8')).get('exists', False):
                    await contract.submit_transaction('DeleteAsset', asset_id)
                    print(f"Successfully deleted asset {asset_id}")
                else:
                    print(f"Asset {asset_id} does not exist, skipping deletion")
            except Exception as error:
                print(f"Error checking if asset {asset_id} exists during cleanup: {str(error)}")

        if user_id and contract:
            try:
                exists_result = await contract.evaluate_transaction('UserExists', user_id)
                if exists_result and json.loads(exists_result.decode('utf-8')).get('exists', False):
                    await contract.submit_transaction('DeleteUser', user_id)
                    print(f"Successfully deleted user {user_id}")
                else:
                    print(f"User {user_id} does not exist, skipping deletion")
            except Exception as error:
                print(f"Error checking if user {user_id} exists during cleanup: {str(error)}")
    except Exception as e:
        print(f"Cleanup failed for asset {asset_id} or user {user_id}: {str(e)}")

async def cleanup_assets_batch(contract, asset_ids: List[str]):
    batch_size = 5
    for i in range(0, len(asset_ids), batch_size):
        batch = asset_ids[i:i + batch_size]
        await asyncio.gather(*[cleanup_test_data(contract, asset_id, None) for asset_id in batch])
        print(f"Completed cleanup batch {i // batch_size + 1}/{len(asset_ids) // batch_size + 1}")
        await asyncio.sleep(DELAY_MS)

def hybrid_encrypt(fragment: Any, public_key: str) -> Dict:
    plaintext = json.dumps(fragment).encode('utf-8') if not isinstance(fragment, str) else fragment.encode('utf-8')
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(plaintext) + encryptor.finalize()
    auth_tag = encryptor.tag

    public_key_obj = serialization.load_pem_public_key(public_key.encode('utf-8'))
    wrapped_key = public_key_obj.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return {
        'encryptedData': b64encode(encrypted_data).decode('utf-8'),
        'iv': b64encode(iv).decode('utf-8'),
        'authTag': b64encode(auth_tag).decode('utf-8'),
        'wrappedKey': b64encode(wrapped_key).decode('utf-8')
    }

async def measure_function(contract, function_name: str, args: List[Any], is_query: bool) -> Dict:
    start_time = asyncio.get_event_loop().time() * 1000
    try:
        if any(arg is None for arg in args):
            print(f"Arguments for {function_name}: {args}")
            return {'duration': -1, 'result': None}

        if function_name == 'CreateUser':
            try:
                exists_result = await contract.evaluate_transaction('UserExists', args[0])
                if exists_result and json.loads(exists_result.decode('utf-8')).get('exists', False):
                    print(f"User {args[0]} already exists, deleting and recreating...")
                    await contract.submit_transaction('DeleteUser', args[0])
            except Exception as error:
                print(f"Error checking if user {args[0]} exists: {str(error)}")

        elif function_name in ['CreateAsset', 'UpdateAsset']:
            try:
                exists_result = await contract.evaluate_transaction('AssetExists', args[0])
                if function_name == 'CreateAsset' and exists_result and json.loads(exists_result.decode('utf-8')).get('exists', False):
                    print(f"Asset {args[0]} already exists, deleting and recreating...")
                    await contract.submit_transaction('DeleteAsset', args[0])
                if function_name == 'UpdateAsset' and (not exists_result or not json.loads(exists_result.decode('utf-8')).get('exists', False)):
                    print(f"Asset {args[0]} does not exist, skipping update")
                    return {'duration': -1, 'result': None}
            except Exception as error:
                print(f"Error checking if asset {args[0]} exists: {str(error)}")
                return {'duration': -1, 'result': None}

            key = generate_random_access_key()
            hash_access_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
            fragments = generate_shamir_fragments(key, 2, 2)

            worker1_path = Path(__file__).parent / 'workers' / 'w1-keys.json'
            worker2_path = Path(__file__).parent / 'workers' / 'w2-keys.json'
            try:
                with open(worker1_path, 'r') as f:
                    w1_keys = json.load(f)
                with open(worker2_path, 'r') as f:
                    w2_keys = json.load(f)
            except Exception as error:
                print(f"Error reading worker key files: {str(error)}")
                raise

            encrypted_fragments = [
                {
                    'byKey1': hybrid_encrypt(fragment, w1_keys['publicKey']),
                    'byKey2': hybrid_encrypt(fragment, w2_keys['publicKey'])
                }
                for fragment in fragments['fragments_map']
            ]

            args[10] = hash_access_key
            args[11] = json.dumps(encrypted_fragments)
            args[12] = json.dumps(fragments['hashedAttributes'])
            args[13] = args[13] or json.dumps([{'interest': ['tech'], 'languages': ['en']}])

        elif function_name == 'PromoteAccess':
            try:
                asset_result = await contract.evaluate_transaction('ReadAsset', args[1])
                asset = json.loads(asset_result.decode('utf-8')) if asset_result else None
                if not asset:
                    print(f"Asset {args[1]} not found, skipping PromoteAccess")
                    return {'duration': -1, 'result': None}
                promoted_access = asset.get('promotedAccess', [])
                if any(access['username'] == args[0] for access in promoted_access):
                    print(f"User {args[0]} already promoted for asset {args[1]}, skipping")
                    return {'duration': -1, 'result': None}
            except Exception as error:
                print(f"Error reading asset {args[1]}: {str(error)}")
                return {'duration': -1, 'result': None}

        elif function_name == 'CheckAccess':
            try:
                asset_result = await contract.evaluate_transaction('ReadAsset', args[1])
                user_result = await contract.evaluate_transaction('GetUser', args[0])
                asset = json.loads(asset_result.decode('utf-8')) if asset_result else None
                user = json.loads(user_result.decode('utf-8')) if user_result else None
                if not asset or not user:
                    print(f"Asset {args[1]} or user {args[0]} not found, skipping CheckAccess")
                    return {'duration': -1, 'result': None}
            except Exception as error:
                print(f"Error validating asset {args[1]} or user {args[0]} for CheckAccess: {str(error)}")
                return {'duration': -1, 'result': None}

        elif function_name == 'RevokePermanentAccess':
            try:
                asset_result = await contract.evaluate_transaction('ReadAsset', args[1])
                asset = json.loads(asset_result.decode('utf-8')) if asset_result else None
                if not asset:
                    print(f"Asset {args[1]} not found, skipping RevokePermanentAccess")
                    return {'duration': -1, 'result': None}
                revoked_access = asset.get('revokedAccess', [])
                if any(access['username'] == args[0] for access in revoked_access):
                    print(f"User {args[0]} already revoked for asset {args[1]}, skipping")
                    return {'duration': -1, 'result': None}
            except Exception as error:
                print(f"Error reading asset {args[1]}: {str(error)}")
                return {'duration': -1, 'result': None}

        elif function_name == 'GrantAccess':
            try:
                asset_result = await contract.evaluate_transaction('ReadAsset', args[1])
                asset = json.loads(asset_result.decode('utf-8')) if asset_result else None
                if not asset:
                    print(f"Asset {args[1]} not found, skipping GrantAccess")
                    return {'duration': -1, 'result': None}
                requesters = asset.get('Requesters', [])
                if any(requester['username'] == args[0] for requester in requesters):
                    print(f"User {args[0]} already has access to asset {args[1]}, skipping")
                    return {'duration': -1, 'result': None}
            except Exception as error:
                print(f"Error reading asset {args[1]}: {str(error)}")
                return {'duration': -1, 'result': None}

        result = await (contract.evaluate_transaction(function_name, *args) if is_query else
                        contract.submit_transaction(function_name, *args))
        end_time = asyncio.get_event_loop().time() * 1000
        return {'duration': end_time - start_time, 'result': result}
    except Exception as error:
        print(f"Error measuring {function_name} with args {args}: {str(error)}")
        return {'duration': -1, 'result': None}

async def benchmark_api_and_query() -> Dict:
    results = {'apiCalls': [], 'queryLatency': []}
    gateway = None
    contract = None
    test_data = None

    try:
        print('Connecting to gateway for API and query benchmark...')
        gateway = await connect_to_user_gateway(USERNAME, 'owner')
        network = await gateway.get_network(CHANNEL_NAME)
        contract = network.get_contract(CHAINCODE_NAME)

        print('Setting up test data for API and query benchmark...')
        test_data = await setup_test_data(contract)
        user_id, asset_id, owner = test_data['userId'], test_data['assetId'], test_data['owner']
        runs = 5
        concurrency_levels = [5, 80, 200, 400, 600, 1000]

        policy_attributes = [{'interest': ['tech'], 'languages': ['en']}]
        new_user_id = generate_unique_id('user')
        new_asset_id = generate_unique_id('asset')
        current_date = datetime.now().isoformat()
        key = generate_random_access_key()
        hash_access_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
        fragments = generate_shamir_fragments(key, 2, 2)

        api_functions = [
            {'name': 'UserExists', 'args': [user_id], 'isQuery': True},
            {'name': 'GetUser', 'args': [user_id], 'isQuery': True},
            {'name': 'GetAssetsByOwnerAndName', 'args': [owner, 'TestAsset', 'DEMO'], 'isQuery': True},
            {'name': 'AssetExists', 'args': [asset_id], 'isQuery': True},
            {'name': 'ReadAsset', 'args': [asset_id], 'isQuery': True},
            {'name': 'CheckAccess', 'args': [user_id, asset_id], 'isQuery': True},
            {'name': 'GetAllAssets', 'args': [], 'isQuery': True},
            {
                'name': 'CreateUser',
                'args': [new_user_id, 'testRole', current_date, 'dummy-public-key', json.dumps(policy_attributes)],
                'isQuery': False
            },
            {
                'name': 'CreateAsset',
                'args': [
                    new_asset_id, json.dumps({'description': 'Test asset'}), json.dumps(policy_attributes),
                    'dummy-public-key', current_date, current_date, owner, 'test-asset', 'dummy-cid', '',
                    hash_access_key, json.dumps(fragments['fragments_map']),
                    json.dumps(fragments['hashedAttributes']),
                    json.dumps([{'interest': ['tech'], 'languages': ['en']}])
                ],
                'isQuery': False
            },
            {
                'name': 'UpdateAsset',
                'args': [
                    asset_id, json.dumps({'description': 'Updated asset'}), json.dumps(policy_attributes),
                    'dummy-public-key', current_date, current_date, owner, 'TestAsset', 'dummy-cid', '',
                    hash_access_key, json.dumps(fragments['fragments_map']),
                    json.dumps(fragments['hashedAttributes']),
                    json.dumps([{'interest': ['tech'], 'languages': ['en']}])
                ],
                'isQuery': False
            },
            {'name': 'RevokePermanentAccess', 'args': [user_id, asset_id, current_date], 'isQuery': False},
            {'name': 'GrantAccess', 'args': [user_id, asset_id, current_date], 'isQuery': False}
        ]

        for func in api_functions:
            total_time = 0
            successful_runs = 0
            print(f"Benchmarking API call {func['name']}...")
            if func['isQuery']:
                outcomes = await asyncio.gather(*[
                    measure_function(contract, func['name'], func['args'], func['isQuery'])
                    for _ in range(runs)
                ])
                for outcome in outcomes:
                    if outcome['duration'] >= 0:
                        total_time += outcome['duration']
                        successful_runs += 1
            else:
                for i in range(runs):
                    outcome = await measure_function(contract, func['name'], func['args'], func['isQuery'])
                    if outcome['duration'] >= 0:
                        total_time += outcome['duration']
                        successful_runs += 1
                    await asyncio.sleep(DELAY_MS)

            avg_latency = round(total_time / successful_runs, 3) if successful_runs > 0 else -1
            results['apiCalls'].append({
                'function': func['name'],
                'avgLatency': avg_latency,
                'latencyUnit': 'milliseconds',
                'successfulRuns': successful_runs,
                'totalRuns': runs
            })

        for concurrency in concurrency_levels:
            print(f"Benchmarking query latency at concurrency {concurrency}...")
            read_start = asyncio.get_event_loop().time()
            read_outcomes = await asyncio.gather(*[
                measure_function(contract, 'ReadAsset', [asset_id], True)
                for _ in range(concurrency)
            ])
            read_total_time = (asyncio.get_event_loop().time() - read_start)
            valid_read_durations = [o['duration'] for o in read_outcomes if o['duration'] >= 0]
            read_avg_latency = sum(valid_read_durations) / len(valid_read_durations) if valid_read_durations else -1
            read_tps = len(valid_read_durations) / read_total_time if read_total_time > 0 else -1

            assets_start = asyncio.get_event_loop().time()
            assets_outcomes = await asyncio.gather(*[
                measure_function(contract, 'GetAssetsByOwnerAndName', [owner, 'TestAsset', 'DEMO'], True)
                for _ in range(concurrency)
            ])
            assets_total_time = (asyncio.get_event_loop().time() - assets_start)
            valid_assets_durations = [o['duration'] for o in assets_outcomes if o['duration'] >= 0]
            assets_avg_latency = sum(valid_assets_durations) / len(valid_assets_durations) if valid_assets_durations else -1
            assets_tps = len(valid_assets_durations) / assets_total_time if assets_total_time > 0 else -1

            results['queryLatency'].append({
                'concurrency': concurrency,
                'readAssetAvgLatency': round(read_avg_latency, 3),
                'readAssetTPS': round(read_tps, 2),
                'getAssetsByOwnerAndNameAvgLatency': round(assets_avg_latency, 3),
                'getAssetsByOwnerAndNameTPS': round(assets_tps, 2)
            })

        print('Writing API and query benchmark results to file...')
        with open(Path(__file__).parent / 'api_and_query_benchmark.json', 'w') as f:
            json.dump(results, f, indent=2)

        return results
    except Exception as error:
        print(f"Error in benchmark_api_and_query: {str(error)}")
        raise
    finally:
        if test_data and contract:
            print('Cleaning up test data for API and query benchmark...')
            await cleanup_test_data(contract, test_data['assetId'], test_data['userId'])
            await cleanup_test_data(contract, new_asset_id, new_user_id)
        if gateway:
            print('Disconnecting gateway for API and query benchmark...')
            await gateway.close()

async def benchmark_create_asset() -> Dict:
    runs = 50
    batch_size = 5
    gateway = None
    contract = None
    asset_ids = []

    try:
        print('Connecting to gateway for create asset benchmark...')
        gateway = await connect_to_user_gateway(USERNAME, 'owner')
        network = await gateway.get_network(CHANNEL_NAME)
        contract = network.get_contract(CHAINCODE_NAME)

        total_time = 0
        successful_runs = 0

        async def create_asset():
            asset_id = generate_unique_id('asset')
            asset_ids.append(asset_id)
            meta_data = json.dumps({'description': 'Test asset'})
            policy_attributes = [{'interest': ['tech'], 'languages': ['en']}]
            policy_set = json.dumps(policy_attributes)
            public_key_owner = 'dummy-public-key'
            now = datetime.now().isoformat()
            owner = USERNAME
            name = 'test-asset'
            cid = 'dummy-cid'
            prev_cid = ''
            key = generate_random_access_key()
            hash_access_key = hashlib.sha256(key.encode('utf-8')).hexdigest()
            fragments = generate_shamir_fragments(key, 2, 2)

            args = [
                asset_id, meta_data, policy_set, public_key_owner, now, now, owner, name, cid, prev_cid,
                hash_access_key,
                json.dumps(fragments['fragments_map']),
                json.dumps(fragments['hashedAttributes']),
                json.dumps([{'interest': ['tech'], 'languages': ['en']}])
            ]
            outcome = await measure_function(contract, 'CreateAsset', args, False)
            return outcome['duration']

        for batch in range(0, runs, batch_size):
            outcomes = await asyncio.gather(*[create_asset() for _ in range(min(batch_size, runs - batch))])
            for duration in outcomes:
                if duration >= 0:
                    total_time += duration
                    successful_runs += 1
            print(f"Completed batch {batch // batch_size + 1}/{runs // batch_size + 1}")
            await asyncio.sleep(DELAY_MS)

        print('Cleaning up assets...')
        await cleanup_assets_batch(contract, asset_ids)

        avg_latency = round(total_time / successful_runs, 3) if successful_runs > 0 else -1
        output = {
            'results': {
                'runs': runs,
                'avgLatency': avg_latency,
                'latencyUnit': 'milliseconds',
                'successfulRuns': successful_runs,
                'totalRuns': runs
            }
        }

        print('Writing create asset benchmark results to file...')
        with open(Path(__file__).parent / 'create_asset_benchmark.json', 'w') as f:
            json.dump(output, f, indent=2)

        return output
    except Exception as error:
        print(f"Error in benchmark_create_asset: {str(error)}")
        raise
    finally:
        if gateway:
            print('Disconnecting gateway for create asset benchmark...')
            await gateway.close()

async def benchmark_promote_demote() -> List[Dict]:
    results = []
    gateway = None
    contract = None
    test_data = None

    try:
        print('Connecting to gateway for promote/demote benchmark...')
        gateway = await connect_to_user_gateway(USERNAME, 'owner')
        network = await gateway.get_network(CHANNEL_NAME)
        contract = network.get_contract(CHAINCODE_NAME)

        print('Setting up test data for promote/demote benchmark...')
        test_data = await setup_test_data(contract)
        user_id, asset_id = test_data['userId'], test_data['assetId']
        current_date = datetime.now().isoformat()

        user_exists = True
        try:
            user_exists_result = await contract.evaluate_transaction('UserExists', user_id)
            user_exists = json.loads(user_exists_result.decode('utf-8')).get('exists', False) if user_exists_result else False
        except Exception as error:
            print(f"Error validating user {user_id}: {str(error)}")

        if not user_exists:
            raise ValueError(f"User {user_id} does not exist after setup")

        functions = [
            {
                'name': 'CheckAccess',
                'args': [user_id, asset_id],
                'isQuery': True,
                'description': 'Check if user can get access'
            },
            {
                'name': 'PromoteAccess',
                'args': [user_id, asset_id, current_date],
                'isQuery': False,
                'description': 'Promote user access'
            },
            {
                'name': 'DemoteAccess',
                'args': [user_id, asset_id, current_date],
                'isQuery': False,
                'description': 'Demote user access'
            }
        ]

        for func in functions:
            total_time = 0
            successful_runs = 0
            total_runs = 5
            print(f"Benchmarking {func['name']}...")

            for i in range(total_runs):
                try:
                    outcome = await measure_function(contract, func['name'], func['args'], func['isQuery'])
                    if outcome['duration'] >= 0:
                        total_time += outcome['duration']
                        successful_runs += 1
                        print(f"{func['name']} run {i + 1} successful, duration: {outcome['duration']}ms")
                        if func['name'] == 'PromoteAccess':
                            post_promote_asset = await contract.evaluate_transaction('ReadAsset', asset_id)
                            post_promote_asset_data = json.loads(post_promote_asset.decode('utf-8')) if post_promote_asset else None
                            print(f"Post-promote asset state for run {i + 1}: {json.dumps(post_promote_asset_data, indent=2)}")
                    else:
                        print(f"{func['name']} failed for run {i + 1}, outcome: {outcome}")
                except Exception as error:
                    print(f"Error in {func['name']} run {i + 1}: {str(error)}")
                await asyncio.sleep(DELAY_MS)

            avg_latency = round(total_time / successful_runs, 3) if successful_runs > 0 else -1
            results.append({
                'function': func['name'],
                'description': func['description'],
                'avgLatency': avg_latency,
                'latencyUnit': 'milliseconds',
                'successfulRuns': successful_runs,
                'totalRuns': total_runs
            })

        print('Writing promote/demote benchmark results to file...')
        with open(Path(__file__).parent / 'promote_demote_benchmark.json', 'w') as f:
            json.dump(results, f, indent=2)

        return results
    except Exception as error:
        print(f"Error in benchmark_promote_demote: {str(error)}")
        raise
    finally:
        if test_data and contract:
            print('Cleaning up test data for promote/demote benchmark...')
            await cleanup_test_data(contract, test_data['assetId'], test_data['userId'])
        if gateway:
            print('Disconnecting gateway for promote/demote benchmark...')
            await gateway.close()

async def benchmark_promotion_check_by_attribute_count() -> List[Dict]:
    attribute_counts = [1, 5, 10, 50, 100, 500]
    runs_per_count = 5
    results = []
    gateway = None
    contract = None
    test_data = None
    user_ids = []

    try:
        print('Connecting to gateway for promotion check benchmark...')
        gateway = await connect_to_user_gateway(USERNAME, 'owner')
        network = await gateway.get_network(CHANNEL_NAME)
        contract = network.get_contract(CHAINCODE_NAME)

        print('Setting up test data for promotion check benchmark...')
        test_data = await setup_test_data(contract)
        asset_id = test_data['assetId']

        for attribute_count in attribute_counts:
            print(f"Benchmarking CheckAccess with {attribute_count} attributes...")
            total_time = 0
            successful_runs = 0
            access_granted_count = 0

            for _ in range(runs_per_count):
                include_required = random.random() < 0.5
                user_id = generate_unique_id('user')
                user_ids.append(user_id)
                policy_set = generate_user_policy_set(attribute_count, include_required)
                current_date = datetime.now().isoformat()

                try:
                    try:
                        await contract.submit_transaction('DeleteUser', user_id)
                    except:
                        pass
                    await contract.submit_transaction(
                        'CreateUser',
                        user_id,
                        'requester',
                        current_date,
                        'dummy-public-key',
                        policy_set
                    )
                    print(f"Created user {user_id} with {attribute_count} attributes, include_required={include_required}")
                except Exception as error:
                    print(f"Error creating user {user_id} with {attribute_count} attributes: {str(error)}")
                    continue

                outcome = await measure_function(contract, 'CheckAccess', [user_id, asset_id], True)
                if outcome['duration'] >= 0:
                    total_time += outcome['duration']
                    successful_runs += 1
                    try:
                        result = json.loads(outcome['result'].decode('utf-8'))
                        if result.get('access', False):
                            access_granted_count += 1
                            print(f"CheckAccess for user {user_id}: Access granted")
                        else:
                            print(f"CheckAccess for user {user_id}: Access denied")
                    except Exception as error:
                        print(f"Error processing CheckAccess result for user {user_id}: {str(error)}")

            avg_latency = round(total_time / successful_runs, 3) if successful_runs > 0 else -1
            access_granted_rate = round(access_granted_count / successful_runs, 3) if successful_runs > 0 else 0
            results.append({
                'attributeCount': attribute_count,
                'avgLatency': avg_latency,
                'latencyUnit': 'milliseconds',
                'successfulRuns': successful_runs,
                'totalRuns': runs_per_count,
                'accessGrantedCount': access_granted_count,
                'accessGrantedRate': access_granted_rate
            })
            print(f"Completed {attribute_count} attributes: "
                  f"avgLatency={avg_latency}ms, successfulRuns={successful_runs}/{runs_per_count}, "
                  f"accessGrantedRate={access_granted_rate}")

        print('Writing promotion check benchmark results to file...')
        with open(Path(__file__).parent / 'promotion_check_benchmark.json', 'w') as f:
            json.dump(results, f, indent=2)

        return results
    except Exception as error:
        print(f"Error in benchmark_promotion_check_by_attribute_count: {str(error)}")
        raise
    finally:
        if test_data and contract:
            print('Cleaning up test data for promotion check benchmark...')
            await cleanup_test_data(contract, test_data['assetId'], test_data['userId'])
            for user_id in user_ids:
                await cleanup_test_data(contract, None, user_id)
        if gateway:
            print('Disconnecting gateway for promotion check benchmark...')
            await gateway.close()

async def benchmark_least_privilege() -> List[Dict]:
    results = []
    gateway = None
    contract = None
    test_data = None

    try:
        print('Connecting to gateway for least privilege benchmark...')
        gateway = await connect_to_user_gateway(USERNAME, 'owner')
        network = await gateway.get_network(CHANNEL_NAME)
        contract = network.get_contract(CHAINCODE_NAME)

        print('Setting up test data for least privilege benchmark...')
        test_data = await setup_test_data(contract)
        user_id, asset_id = test_data['userId'], test_data['assetId']
        current_date = datetime.now().isoformat()

        # Test 1: User with insufficient attributes should not have access
        print('Running least privilege test 1: User with insufficient attributes...')
        insufficient_user_id = generate_unique_id('user')
        insufficient_policy = json.dumps([{'interest': ['finance'], 'languages': ['fr']}])
        try:
            await contract.submit_transaction(
                'CreateUser',
                insufficient_user_id,
                'requester',
                current_date,
                'dummy-public-key',
                insufficient_policy
            )
            check_access_result = await contract.evaluate_transaction('CheckAccess', insufficient_user_id, asset_id)
            access_result = json.loads(check_access_result.decode('utf-8')) if check_access_result else None
            status = 'passed' if not access_result.get('access', True) else 'failed'
            results.append({
                'test': 'Insufficient Attributes',
                'status': status,
                'description': 'User with insufficient attributes should not have access'
            })
            print(f"Test 1 {'passed' if status == 'passed' else 'failed'}: Access {'denied' if not access_result.get('access', True) else 'granted'}")
        except Exception as error:
            results.append({
                'test': 'Insufficient Attributes',
                'status': 'failed',
                'description': 'User with insufficient attributes should not have access',
                'error': str(error)
            })
            print(f"Test 1 failed: {str(error)}")

        # Test 2: Revoked user should not have access
        print('Running least privilege test 2: Revoked user access...')
        try:
            await contract.submit_transaction('RevokePermanentAccess', user_id, asset_id, current_date)
            check_access_result = await contract.evaluate_transaction('CheckAccess', user_id, asset_id)
            access_result = json.loads(check_access_result.decode('utf-8')) if check_access_result else None
            status = 'passed' if not access_result.get('access', True) else 'failed'
            results.append({
                'test': 'Revoked Access',
                'status': status,
                'description': 'Revoked user should not have access'
            })
            print(f"Test 2 {'passed' if status == 'passed' else 'failed'}: Access {'denied' if not access_result.get('access', True) else 'granted'}")
        except Exception as error:
            results.append({
                'test': 'Revoked Access',
                'status': 'failed',
                'description': 'Revoked user should not have access',
                'error': str(error)
            })
            print(f"Test 2 failed: {str(error)}")

        # Test 3: Restored access should allow access
        print('Running least privilege test 3: Restored access...')
        try:
            await contract.submit_transaction('RestoreAccess', user_id, asset_id, current_date)
            check_access_result = await contract.evaluate_transaction('CheckAccess', user_id, asset_id)
            access_result = json.loads(check_access_result.decode('utf-8')) if check_access_result else None
            status = 'passed' if access_result.get('access', False) else 'failed'
            results.append({
                'test': 'Restored Access',
                'status': status,
                'description': 'Restored user should have access'
            })
            print(f"Test 3 {'passed' if status == 'passed' else 'failed'}: Access {'granted' if access_result.get('access', False) else 'denied'}")
        except Exception as error:
            results.append({
                'test': 'Restored Access',
                'status': 'failed',
                'description': 'Restored user should have access',
                'error': str(error)
            })
            print(f"Test 3 failed: {str(error)}")

        print('Writing least privilege benchmark results to file...')
        with open(Path(__file__).parent / 'least_privilege_benchmark.json', 'w') as f:
            json.dump(results, f, indent=2)

        await save_results_to_csv({'results': results}, 'least_privilege', 'single_run')

        return results
    except Exception as error:
        print(f"Error in benchmark_least_privilege: {str(error)}")
        raise
    finally:
        if test_data and contract:
            print('Cleaning up test data for least privilege benchmark...')
            await cleanup_test_data(contract, test_data['assetId'], test_data['userId'])
            await cleanup_test_data(contract, None, insufficient_user_id)
        if gateway:
            print('Disconnecting gateway for least privilege benchmark...')
            await gateway.close()

async def main():
    iteration_counts = [1, 5, 10]
    try:
        print('Starting benchmark suite...')
        await run_benchmark_with_iterations(benchmark_create_asset, iteration_counts, 'create_asset')
        await run_benchmark_with_iterations(benchmark_api_and_query, iteration_counts, 'api_and_query')
        await run_benchmark_with_iterations(benchmark_promote_demote, iteration_counts, 'promote_demote')
        await run_benchmark_with_iterations(benchmark_promotion_check_by_attribute_count, iteration_counts, 'promotion_check_by_attribute_count')
        await benchmark_least_privilege()
        print('Benchmark suite completed successfully.')
    except Exception as error:
        print(f"Error running benchmark suite: {str(error)}")
        raise

if __name__ == '__main__':
    asyncio.run(main())
