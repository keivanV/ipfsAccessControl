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
csv_folder = "./dataset"
csv_folder = os.path.expanduser(csv_folder)

# Find all CSV files (exclude :Zone.Identifier)
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
            'Total Decrypt Time (ms)': 'Decrypt Time (ms)'
        }
        df = df.rename(columns=column_map)
        # Add Source column
        df['Source'] = os.path.basename(file).replace('.csv', '')
        # Ensure required columns exist
        required_cols = ['Files', 'Attributes']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            print(f"File {file} missing required columns: {', '.join(missing_cols)}. Skipping...")
            continue
        # Remove duplicate columns
        df = df.loc[:, ~df.columns.duplicated()]
        # Filter to only relevant columns
        relevant_cols = ['Files', 'Attributes', 'Encrypt Time (ms)', 'Decrypt Time (ms)', 'Source']
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
print(f"Comparing keys: {', '.join(compare_keys)}")

# Function to create and save a single plot with all sources
def create_plot(filtered_df, x_col, key, fixed_col, fixed_value, output_file):
    plt.figure(figsize=(6, 4))
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
        if len(x) > 1:
            x_smooth = np.linspace(x.min(), x.max(), 100)
            try:
                f = interp1d(x, y, kind='cubic')
                y_smooth = f(x_smooth)
                plt.plot(x_smooth, y_smooth, label=f'{source}')
                plt.scatter(x, y, marker='o', s=20)
            except ValueError as e:
                print(f"Error in interpolation for Source={source}, {fixed_col}={fixed_value}: {e}. Falling back to linear plot.")
                plt.plot(x, y, marker='o', label=f'{source}')
        else:
            plt.plot(x, y, marker='o', label=f'{source}')
    
    plt.title(f'{key} ({fixed_col}={fixed_value})')
    plt.xlabel(x_col)
    plt.ylabel(key)
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(output_file, bbox_inches='tight')
    plt.close()
    print(f"Saved individual plot: {output_file}")

# Combined plot: 2x2 subplot layout
fig, axes = plt.subplots(2, 2, figsize=(12, 8))
axes = axes.flatten()
plot_idx = 0

# Plot Type 1: Fixed Attributes = 14, Variable Files
attributes_fixed = 14
filtered_df = combined_df[combined_df['Attributes'] == attributes_fixed]
if filtered_df.empty:
    print(f"No data found for fixed Attributes={attributes_fixed}")
else:
    filtered_df = filtered_df.sort_values('Files')
    print(f"Data for fixed Attributes={attributes_fixed}: {len(filtered_df)} rows from sources: {', '.join(filtered_df['Source'].unique())}")
    for key in compare_keys:
        if key not in filtered_df.columns or filtered_df[key].isna().all():
            print(f"Key '{key}' not found or all values are NaN for fixed Attributes={attributes_fixed}. Skipping...")
            continue
        ax = axes[plot_idx]
        for source in filtered_df['Source'].unique():
            source_df = filtered_df[filtered_df['Source'] == source]
            if key in source_df.columns and not source_df[key].isna().all():
                if source_df['Files'].duplicated().any():
                    print(f"Warning: Duplicate Files found for Source={source}, Attributes={attributes_fixed}. Aggregating by mean.")
                    source_df = source_df.groupby('Files').agg({key: 'mean'}).reset_index()
                
                x = source_df['Files'].values
                y = source_df[key].values
                if len(x) > 1:
                    x_smooth = np.linspace(x.min(), x.max(), 100)
                    try:
                        f = interp1d(x, y, kind='cubic')
                        y_smooth = f(x_smooth)
                        ax.plot(x_smooth, y_smooth, label=f'{source}')
                        ax.scatter(x, y, marker='o', s=20)
                    except ValueError as e:
                        print(f"Error in interpolation for Source={source}, Attributes={attributes_fixed}: {e}. Falling back to linear plot.")
                        ax.plot(x, y, marker='o', label=f'{source}')
                else:
                    ax.plot(x, y, marker='o', label=f'{source}')
        
        ax.set_title(f'{key} (Attributes={attributes_fixed})')
        ax.set_xlabel('Files')
        ax.set_ylabel(key)
        ax.legend(fontsize=8)
        # Save individual plot with all sources
        output_file = os.path.join(csv_folder, f'plot_attributes_{attributes_fixed}_{key.replace(" ", "_").lower()}.png')
        create_plot(filtered_df, 'Files', key, 'Attributes', attributes_fixed, output_file)
        plot_idx += 1

# Plot Type 2: Fixed Files = 14, Variable Attributes
files_fixed = 14
filtered_df = combined_df[combined_df['Files'] == files_fixed]
if filtered_df.empty:
    print(f"No data found for fixed Files={files_fixed}")
else:
    filtered_df = filtered_df.sort_values('Attributes')
    print(f"Data for fixed Files={files_fixed}: {len(filtered_df)} rows from sources: {', '.join(filtered_df['Source'].unique())}")
    for key in compare_keys:
        if key not in filtered_df.columns or filtered_df[key].isna().all():
            print(f"Key '{key}' not found or all values are NaN for fixed Files={files_fixed}. Skipping...")
            continue
        ax = axes[plot_idx]
        for source in filtered_df['Source'].unique():
            source_df = filtered_df[filtered_df['Source'] == source]
            if key in source_df.columns and not source_df[key].isna().all():
                if source_df['Attributes'].duplicated().any():
                    print(f"Warning: Duplicate Attributes found for Source={source}, Files={files_fixed}. Aggregating by mean.")
                    source_df = source_df.groupby('Attributes').agg({key: 'mean'}).reset_index()
                
                x = source_df['Attributes'].values
                y = source_df[key].values
                if len(x) > 1:
                    x_smooth = np.linspace(x.min(), x.max(), 100)
                    try:
                        f = interp1d(x, y, kind='cubic')
                        y_smooth = f(x_smooth)
                        ax.plot(x_smooth, y_smooth, label=f'{source}')
                        ax.scatter(x, y, marker='o', s=20)
                    except ValueError as e:
                        print(f"Error in interpolation for Source={source}, Files={files_fixed}: {e}. Falling back to linear plot.")
                        ax.plot(x, y, marker='o', label=f'{source}')
                else:
                    ax.plot(x, y, marker='o', label=f'{source}')
        
        ax.set_title(f'{key} (Files={files_fixed})')
        ax.set_xlabel('Attributes')
        ax.set_ylabel(key)
        ax.legend(fontsize=8)
        # Save individual plot with all sources
        output_file = os.path.join(csv_folder, f'plot_files_{files_fixed}_{key.replace(" ", "_").lower()}.png')
        create_plot(filtered_df, 'Attributes', key, 'Files', files_fixed, output_file)
        plot_idx += 1

# Save combined plot
plt.tight_layout()
output_file = os.path.join(csv_folder, 'combined_four_plots.png')
plt.savefig(output_file, bbox_inches='tight')
plt.close()
print(f"Combined plot with 4 subplots saved: {output_file}")

print("All plots generated successfully!")