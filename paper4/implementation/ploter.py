import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the CSV file
csv_file = "detailed_benchmark_results.csv"
df = pd.read_csv(csv_file)

# Set up the figure with 4 subplots (2x2 grid)
plt.figure(figsize=(12, 8))
sns.set(style="whitegrid")

# Colors for different fixed counts
colors = sns.color_palette("husl", 7)  # 7 distinct colors for 2, 4, 6, 8, 10, 12, 14

# Subplot 1: Encryption time with fixed files and varying attributes
plt.subplot(2, 2, 1)
fixed_files = [2, 4, 6, 8, 10, 12, 14]
for i, f in enumerate(fixed_files):
    subset = df[(df['Scenario'].str.contains(f'Fixed_Files_{f}_Attrs')) & (df['Files'] == f)]
    plt.plot(subset['Attributes'], subset['Encrypt Time (ms)'], marker='o', label=f'{f} Files', color=colors[i])
plt.title('Encryption Time (Fixed Files, Varying Attributes)')
plt.xlabel('Number of Attributes')
plt.ylabel('Time (ms)')
plt.legend(title='Fixed Files')
plt.grid(True)

# Subplot 2: Decryption time with fixed files and varying attributes
plt.subplot(2, 2, 2)
for i, f in enumerate(fixed_files):
    subset = df[(df['Scenario'].str.contains(f'Fixed_Files_{f}_Attrs')) & (df['Files'] == f)]
    plt.plot(subset['Attributes'], subset['Decrypt Time (ms)'] , marker='o', label=f'{f} Files', color=colors[i])
plt.title('Decryption Time (Fixed Files, Varying Attributes)')
plt.xlabel('Number of Attributes')
plt.ylabel('Time (ms)')
plt.legend(title='Fixed Files')
plt.grid(True)

# Subplot 3: Encryption time with fixed attributes and varying files
plt.subplot(2, 2, 3)
fixed_attrs = [2, 4, 6, 8, 10, 12, 14]
for i, a in enumerate(fixed_attrs):
    subset = df[(df['Scenario'].str.contains(f'Fixed_Attrs_{a}_Files')) & (df['Attributes'] == a)]
    plt.plot(subset['Files'], subset['Encrypt Time (ms)'] , marker='o', label=f'{a} Attributes', color=colors[i])
plt.title('Encryption Time (Fixed Attributes, Varying Files)')
plt.xlabel('Number of Files')
plt.ylabel('Time (ms)')
plt.legend(title='Fixed Attributes')
plt.grid(True)

# Subplot 4: Decryption time with fixed attributes and varying files
plt.subplot(2, 2, 4)
for i, a in enumerate(fixed_attrs):
    subset = df[(df['Scenario'].str.contains(f'Fixed_Attrs_{a}_Files')) & (df['Attributes'] == a)]
    plt.plot(subset['Files'], subset['Decrypt Time (ms)'] , marker='o', label=f'{a} Attributes', color=colors[i])
plt.title('Decryption Time (Fixed Attributes, Varying Files)')
plt.xlabel('Number of Files')
plt.ylabel('Time (ms)')
plt.legend(title='Fixed Attributes')
plt.grid(True)

# Adjust layout to prevent overlap
plt.tight_layout()

# Save the plot as an image
plt.savefig('benchmark_plots.png', dpi=300, bbox_inches='tight')
plt.close()

print("Plot saved as 'benchmark_plots.png'")