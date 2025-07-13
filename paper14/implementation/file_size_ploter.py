import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the CSV file
csv_file = "benchmark_results.csv"
df = pd.read_csv(csv_file)

# Filter data for scenarios with Files=1 and Attributes=2
subset = df[(df['Files'] == 1) & (df['Attributes'] == 2)]

# Set up the figure
plt.figure(figsize=(8, 6))
sns.set(style="whitegrid")

# Define colors for encryption and decryption
colors = sns.color_palette("husl", 2)  # Two colors for Encrypt and Decrypt

# Plot Encryption Time vs. Data Size
plt.plot(subset['Data Size (Bytes)'], subset['Encrypt Time (ms)'], marker='o', label='Encryption Time', color=colors[0])

# Plot Decryption Time vs. Data Size
plt.plot(subset['Data Size (Bytes)'], subset['Decrypt Time (ms)'], marker='s', label='Decryption Time', color=colors[1])

# Customize the plot
plt.title('Encryption and Decryption Times (1 File, 2 Attributes)')
plt.xlabel('Data Size')
plt.ylabel('Time (ms)')
plt.xscale('log')  # Log scale for better visualization of data sizes (1KB to 1MB)
plt.xticks(
    subset['Data Size (Bytes)'],
    [f"{size//1024}KB" if size < 1048576 else "1MB" for size in subset['Data Size (Bytes)']]
)  # Label as 1KB, 5KB, 10KB, 50KB, 100KB, 1MB
plt.legend()
plt.grid(True)

# Adjust layout
plt.tight_layout()

# Save the plot as an image
plt.savefig('benchmark_plots_file_size.png', dpi=300, bbox_inches='tight')
plt.savefig('benchmark_plots_file_size.pdf', dpi=300, bbox_inches='tight')
plt.close()

print("Plot saved as 'benchmark_plots_file_size.png'")