import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os
import numpy as np
from scipy.interpolate import interp1d

# Plot settings
sns.set(style="whitegrid")
plt.rcParams['figure.figsize'] = (6, 4)  # Size for individual plots

# CSV folder path
csv_folder = "./dataset_file_size"
csv_folder = os.path.expanduser(csv_folder)

# Create directory if it doesn't exist
if not os.path.exists(csv_folder):
    os.makedirs(csv_folder)

csv_files = [f for f in glob.glob(os.path.join(csv_folder, "*.csv")) if ":Zone.Identifier" not in f]
if not csv_files:
    print("No CSV files found in the folder!")
    exit()
print(f"Found {len(csv_files)} CSV files: {', '.join([os.path.basename(f) for f in csv_files])}")

# Read and combine data
all_data = []
for file in csv_files:
    try:
        df = pd.read_csv(file)
        # Standardize column names
        column_map = {
            'Total Encrypt Time (ms)': 'Encrypt Time (ms)',
            'Total Decrypt Time (ms)': 'Decrypt Time (ms)',
            'Total Encryption Time (ms)': 'Encrypt Time (ms)',  # Added for 15.csv
            'Total Decryption Time (ms)': 'Decrypt Time (ms)'   # Added for 15.csv
        }
        df = df.rename(columns=column_map)
        # Add Source column
        df['Source'] = os.path.basename(file).replace('.csv', '')
        # Ensure required columns exist
        required_cols = ['Files', 'Attributes', 'Data Size (Bytes)']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            print(f"File {file} missing required columns: {', '.join(missing_cols)}. Skipping...")
            continue
        # Remove duplicate columns
        df = df.loc[:, ~df.columns.duplicated()]
        # Filter to relevant columns
        relevant_cols = ['Files', 'Attributes', 'Data Size (Bytes)', 'Encrypt Time (ms)', 'Decrypt Time (ms)', 'Source']
        available_cols = [col for col in relevant_cols if col in df.columns]
        df = df[available_cols]
        all_data.append(df)
        print(f"File {file} read successfully. Columns: {', '.join(df.columns)}")
    except Exception as e:
        print(f"Error reading file {file}: {e}")

if not all_data:
    print("No valid CSV files read!")
    exit()

combined_df = pd.concat(all_data, ignore_index=True)
print(f"Total rows in combined data: {len(combined_df)}")

# Columns to compare
compare_keys = ['Encrypt Time (ms)', 'Decrypt Time (ms)']
available_keys = [key for key in compare_keys if key in combined_df.columns]
print(f"Comparing keys: {', '.join(available_keys)}")

# Function to create and save a single plot with all sources
def create_plot(filtered_df, x_col, key, fixed_col, fixed_value, output_file):
    plt.figure(figsize=(6, 4))
    plotted = False
    for source in filtered_df['Source'].unique():
        source_df = filtered_df[filtered_df['Source'] == source]
        if key not in source_df.columns or source_df[key].isna().all():
            print(f"Key '{key}' not found or all values are NaN for Source={source}, {fixed_col}={fixed_value}. Skipping source...")
            continue
        # Check for duplicates in x_col
        if source_df[x_col].duplicated().any():
            print(f"Warning: Duplicate {x_col} found for Source={source}, {fixed_col}={fixed_value}. Aggregating by mean.")
            source_df = source_df.groupby(x_col).agg({key: 'mean'}).reset_index()
        
        x = source_df[x_col].values
        y = source_df[key].values
        if len(x) < 1:
            continue
        # Sort by x to ensure proper interpolation
        sorted_indices = np.argsort(x)
        x = x[sorted_indices]
        y = y[sorted_indices]
        if len(np.unique(x)) >= 4:  # Cubic interpolation needs at least 4 points
            x_smooth = np.linspace(x.min(), x.max(), 100)
            try:
                f = interp1d(x, y, kind='cubic', fill_value="extrapolate")
                y_smooth = f(x_smooth)
                plt.plot(x_smooth, y_smooth, label=f'{source}')
                plt.scatter(x, y, marker='o', s=20)
            except ValueError as e:
                print(f"Error in interpolation for Source={source}, {fixed_col}={fixed_value}: {e}. Falling back to linear plot.")
                plt.plot(x, y, marker='o', label=f'{source}')
        else:
            print(f"Insufficient unique points ({len(np.unique(x))}) for cubic interpolation for Source={source}, {fixed_col}={fixed_value}. Using linear plot.")
            plt.plot(x, y, marker='o', label=f'{source}')
        plotted = True
    
    if plotted:
        plt.title(f'{key} ({fixed_col}={fixed_value})')
        plt.xlabel(x_col)
        plt.ylabel(key)
        plt.xscale('log')  # Use logarithmic scale for Data Size (Bytes)
        plt.legend(fontsize=8)
        plt.tight_layout()
        plt.savefig(output_file, bbox_inches='tight')
        print(f"Saved individual plot: {output_file}")
    else:
        print(f"No data to plot for {key} ({fixed_col}={fixed_value}). Skipping plot.")
    plt.close()

# Determine fixed values dynamically
attributes_values = combined_df['Attributes'].unique()
attributes_fixed = attributes_values[0] if len(attributes_values) > 0 else None

if attributes_fixed is None:
    print("No valid Attributes values found in the data!")
    exit()

print(f"Using fixed Attributes={attributes_fixed}")

# Combined plot: 1x2 subplot layout
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
axes = axes.flatten() if len(available_keys) > 1 else [axes]  # Handle single key case
plot_idx = 0

# Plot: Fixed Attributes, Variable Data Size (Bytes)
filtered_df = combined_df[combined_df['Attributes'] == attributes_fixed]
if filtered_df.empty:
    print(f"No data found for fixed Attributes={attributes_fixed}")
else:
    filtered_df = filtered_df.sort_values('Data Size (Bytes)')
    print(f"Data for fixed Attributes={attributes_fixed}: {len(filtered_df)} rows from sources: {', '.join(filtered_df['Source'].unique())}")
    for key in available_keys:
        if plot_idx >= len(axes):
            break
        ax = axes[plot_idx]
        plotted = False
        for source in filtered_df['Source'].unique():
            source_df = filtered_df[filtered_df['Source'] == source]
            if key not in source_df.columns or source_df[key].isna().all():
                print(f"Key '{key}' not found or all values are NaN for Source={source}, Attributes={attributes_fixed}. Skipping...")
                continue
            if source_df['Data Size (Bytes)'].duplicated().any():
                print(f"Warning: Duplicate Data Size (Bytes) found for Source={source}, Attributes={attributes_fixed}. Aggregating by mean.")
                source_df = source_df.groupby('Data Size (Bytes)').agg({key: 'mean'}).reset_index()
            
            x = source_df['Data Size (Bytes)'].values
            y = source_df[key].values
            if len(x) < 1:
                continue
            # Sort by x to ensure proper interpolation
            sorted_indices = np.argsort(x)
            x = x[sorted_indices]
            y = y[sorted_indices]
            if len(np.unique(x)) >= 4:  # Cubic interpolation needs at least 4 points
                x_smooth = np.linspace(x.min(), x.max(), 100)
                try:
                    f = interp1d(x, y, kind='cubic', fill_value="extrapolate")
                    y_smooth = f(x_smooth)
                    ax.plot(x_smooth, y_smooth, label=f'{source}')
                    ax.scatter(x, y, marker='o', s=20)
                except ValueError as e:
                    print(f"Error in interpolation for Source={source}, Attributes={attributes_fixed}: {e}. Falling back to linear plot.")
                    ax.plot(x, y, marker='o', label=f'{source}')
            else:
                print(f"Insufficient unique points ({len(np.unique(x))}) for cubic interpolation for Source={source}, Attributes={attributes_fixed}. Using linear plot.")
                ax.plot(x, y, marker='o', label=f'{source}')
            plotted = True
        
        if plotted:
            ax.set_title(f'{key} (Attributes={attributes_fixed})')
            ax.set_xlabel('Data Size (Bytes)')
            ax.set_ylabel(key)
            ax.set_xscale('log')  # Log scale for better visualization
            ax.legend(fontsize=8)
            # Save individual plot
            output_file = os.path.join(csv_folder, f'plot_attributes_{attributes_fixed}_{key.replace(" ", "_").lower()}.png')
            create_plot(filtered_df, 'Data Size (Bytes)', key, 'Attributes', attributes_fixed, output_file)
            plot_idx += 1
        else:
            ax.set_visible(False)

# Save combined plot if any subplots were generated
if plot_idx > 0:
    plt.tight_layout()
    output_file = os.path.join(csv_folder, 'combined_plots.pdf')
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Combined plot with {plot_idx} subplots saved: {output_file}")
else:
    print("No subplots generated for combined plot.")
plt.close()

print("All plots generated successfully!")