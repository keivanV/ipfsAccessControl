
import time
import csv
import logging
import random
from typing import List, Dict, Set
import matplotlib.pyplot as plt
import numpy as np
from tabulate import tabulate
from cr_fh2 import CRFHCPABE, AccessTreeNode, create_access_tree

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def policy_to_string(node: AccessTreeNode, indent: int = 0) -> str:
    """Convert access tree to a human-readable string."""
    if node.type == "leaf":
        return node.attribute
    children_str = [policy_to_string(child, indent + 1) for child in node.children]
    if node.gate_type == "AND":
        gate_str = f"{' AND '.join(children_str)}"
    else:  # OR gate
        gate_str = f"{' OR '.join(children_str)}"
    if len(children_str) > 1:
        gate_str = f"({gate_str})"
    if node.level_node_id:
        gate_str = f"{node.level_node_id}: {gate_str}"
    return gate_str

def run_benchmark():
    """Run benchmark for CR-FH-CPABE with varying files and attributes."""
    cpabe = CRFHCPABE()
    logging.info("Starting benchmark for CR-FH-CPABE...")

    file_counts = [2, 4, 6, 8, 10, 12, 14]
    attr_counts = [2, 4, 6, 8, 10, 12, 14]
    num_runs = 3

    # Data structures to store results
    results = []  # List of dicts for CSV
    policies = {}  # (n_files, n_attrs) -> policy_str

    for n_files in file_counts:
        for n_attrs in attr_counts:
            # Generate attributes for exactly n_attrs
            attributes = [f"attr{i+1}" for i in range(n_attrs)]
            # User gets minimal attributes to satisfy first path, e.g., attr1
            user_attrs = {'attr1'}
            access_tree = create_access_tree(n_attrs, attributes)
            policy_str = policy_to_string(access_tree)
            policies[(n_files, n_attrs)] = policy_str
            logging.info(f"Files={n_files}, Attrs={n_attrs}, Policy: {policy_str}")
            messages = [f"File{i+1}" for i in range(n_files)]

            setup_time = 0
            keygen_time = 0
            encrypt_time = 0
            decrypt_time = 0
            success_count = 0
            sizes = {'MPK': 0, 'MSK': 0, 'SK': 0, 'CT': 0}

            for run in range(num_runs):
                # Setup
                start_time = time.time()
                MPK, MSK = cpabe.setup()
                setup_time += time.time() - start_time

                # Keygen
                start_time = time.time()
                SK = cpabe.keygen(MPK, MSK, user_attrs, f"user_{run+1}")
                keygen_time += time.time() - start_time

                # Encrypt
                start_time = time.time()
                CT = cpabe.encrypt(MPK, messages, access_tree)
                encrypt_time += time.time() - start_time

                # Decrypt
                start_time = time.time()
                decrypted_messages = cpabe.decrypt(MPK, CT, SK, user_attrs)
                decrypt_time += time.time() - start_time

                # Compute sizes
                run_sizes = cpabe.compute_sizes(MPK, MSK, SK, CT)  # Fixed order
                for key in sizes:
                    sizes[key] += run_sizes[key]

                # Check decryption success (expect all files since policy is shared)
                expected = [f"File{i+1}" for i in range(n_files)]
                if sorted(decrypted_messages) == sorted(expected):
                    success_count += 1
                    logging.info(f"Run {run+1}, Files={n_files}, Attrs={n_attrs}: Decryption successful")
                else:
                    logging.warning(f"Run {run+1}, Files={n_files}, Attrs={n_attrs}: Decrypt failed, got {decrypted_messages}")

            # Average results
            avg_setup = setup_time / num_runs
            avg_keygen = keygen_time / num_runs
            avg_encrypt = encrypt_time / num_runs
            avg_decrypt = decrypt_time / num_runs
            success_rate = (success_count / num_runs) * 100
            for key in sizes:
                sizes[key] = sizes[key] // num_runs

            logging.info(f"Files={n_files}, Attrs={n_attrs}, Success Rate={success_rate:.2f}%")

            # Store results
            results.append({
                'Files': n_files,
                'Attrs': n_attrs,
                'Policy': policy_str,
                'Setup Time (s)': avg_setup,
                'Keygen Time (s)': avg_keygen,
                'Encrypt Time (s)': avg_encrypt,
                'Decrypt Time (s)': avg_decrypt,
                'MPK Size (Bytes)': sizes['MPK'],
                'MSK Size (Bytes)': sizes['MSK'],
                'SK Size (Bytes)': sizes['SK'],
                'CT Size (Bytes)': sizes['CT'],
                'Success Rate (%)': success_rate
            })

    # Save to CSV
    csv_headers = ['Files', 'Attrs', 'Policy', 'Setup Time (s)', 'Keygen Time (s)', 
                   'Encrypt Time (s)', 'Decrypt Time (s)', 'MPK Size (Bytes)', 
                   'MSK Size (Bytes)', 'SK Size (Bytes)', 'CT Size (Bytes)', 
                   'Success Rate (%)']
    with open('benchmark_results.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    logging.info("Results saved to CSV")

    # Plot results
    plot_benchmark(file_counts, attr_counts, results)

    # Print tables
    print_performance_tables(file_counts, attr_counts, results)

def plot_benchmark(file_counts: List[int], attr_counts: List[int], results: List[Dict]) -> None:
    """Generate plots for benchmark results."""
    # Prepare data for plotting
    comp_times = {op: np.zeros((len(file_counts), len(attr_counts))) for op in ['Setup', 'Keygen', 'Encrypt', 'Decrypt']}
    comm_sizes = {elem: np.zeros((len(file_counts), len(attr_counts))) for elem in ['MPK', 'MSK', 'SK', 'CT']}
    success_rates = np.zeros((len(file_counts), len(attr_counts)))

    for result in results:
        f_idx = file_counts.index(result['Files'])
        a_idx = attr_counts.index(result['Attrs'])
        comp_times['Setup'][f_idx, a_idx] = result['Setup Time (s)']
        comp_times['Keygen'][f_idx, a_idx] = result['Keygen Time (s)']
        comp_times['Encrypt'][f_idx, a_idx] = result['Encrypt Time (s)']
        comp_times['Decrypt'][f_idx, a_idx] = result['Decrypt Time (s)']
        comm_sizes['MPK'][f_idx, a_idx] = result['MPK Size (Bytes)']
        comm_sizes['MSK'][f_idx, a_idx] = result['MSK Size (Bytes)']
        comm_sizes['SK'][f_idx, a_idx] = result['SK Size (Bytes)']
        comm_sizes['CT'][f_idx, a_idx] = result['CT Size (Bytes)']
        success_rates[f_idx, a_idx] = result['Success Rate (%)']

    # Plot computation times (heatmap)
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Computation Time (s)', fontsize=14)
    operations = ['Setup', 'Keygen', 'Encrypt', 'Decrypt']
    for idx, op in enumerate(operations):
        ax = axes[idx // 2, idx % 2]
        im = ax.imshow(comp_times[op], cmap='viridis', aspect='auto')
        ax.set_title(op)
        ax.set_xticks(np.arange(len(attr_counts)))
        ax.set_yticks(np.arange(len(file_counts)))
        ax.set_xticklabels(attr_counts)
        ax.set_yticklabels(file_counts)
        ax.set_xlabel('Attributes')
        ax.set_ylabel('Files')
        plt.colorbar(im, ax=ax)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('comp_times_heatmap.png')
    plt.close()

    # Plot communication sizes
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Communication Overhead (Bytes)', fontsize=14)
    elements = ['MPK', 'MSK', 'SK', 'CT']
    for idx, elem in enumerate(elements):
        ax = axes[idx // 2, idx % 2]
        im = ax.imshow(comm_sizes[elem], cmap='plasma', aspect='auto')
        ax.set_title(elem)
        ax.set_xticks(np.arange(len(attr_counts)))
        ax.set_yticks(np.arange(len(file_counts)))
        ax.set_xticklabels(attr_counts)
        ax.set_yticklabels(file_counts)
        ax.set_xlabel('Attributes')
        ax.set_ylabel('Files')
        plt.colorbar(im, ax=ax)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('comm_sizes_heatmap.png')
    plt.close()

    # Plot success rates
    fig, ax = plt.subplots(figsize=(8, 7))
    fig.suptitle('Decryption Success Rates (%)', fontsize=14)
    im = ax.imshow(success_rates, cmap='inferno', aspect='auto')
    ax.set_title('Success Rate')
    ax.set_xticks(np.arange(len(attr_counts)))
    ax.set_yticks(np.arange(len(file_counts)))
    ax.set_xticklabels(attr_counts)
    ax.set_yticklabels(file_counts)
    ax.set_xlabel('Attributes')
    ax.set_ylabel('Files')
    plt.colorbar(im, ax=ax)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('success_rates_heatmap.png')
    plt.close()

def print_performance_tables(file_counts: List[int], attr_counts: List[int], results: List[Dict]) -> None:
    """Print tables for benchmark results."""
    for n_files in file_counts:
        print(f"\nPerformance for {n_files} Files:")
        table = [['Attrs', 'Setup (s)', 'Keygen (s)', 'Encrypt (s)', 'Decrypt (s)', 
                  'MPK (B)', 'MSK (B)', 'SK (B)', 'CT (B)', 'Success (%)']]
        for n_attrs in attr_counts:
            result = next(r for r in results if r['Files'] == n_files and r['Attrs'] == n_attrs)
            row = [
                n_attrs,
                round(result['Setup Time (s)'], 6),
                round(result['Keygen Time (s)'], 6),
                round(result['Encrypt Time (s)'], 6),
                round(result['Decrypt Time (s)'], 6),
                result['MPK Size (Bytes)'],
                result['MSK Size (Bytes)'],
                result['SK Size (Bytes)'],
                result['CT Size (Bytes)'],
                round(result['Success Rate (%)'], 1)
            ]
            table.append(row)
        print(tabulate(table, headers='firstrow', tablefmt='grid'))

if __name__ == "__main__":
    run_benchmark()
