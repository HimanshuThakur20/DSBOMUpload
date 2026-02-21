# validate_failed.py
"""Validate failed SBOMs and identify the reason for failure."""

import json
import os
from collections import Counter
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl import load_workbook as load_wb

# Load tags
tags_map = {}
wb = load_wb('Account data.xlsx', read_only=True)
sheet = wb.active
rows = list(sheet.iter_rows(values_only=True))
for row in rows[1:]:
    if row and row[0]:
        acc = str(row[0]).strip()
        tags = [str(c).strip() for c in row[1:] if c]
        tags_map[acc] = tags
wb.close()

# Failed files from upload
failed_filenames = [
    '102809085638_ip-10-45-16-134_052f4305209943ab_2026-02-17T08-16-43Z.json',
    '102809085638_ip-10-45-16-221_0caad2d876e28ec9_2026-02-17T08-16-43Z.json',
    '102809085638_ip-10-45-16-242_22619e08e7e2c7e2_2026-02-17T08-16-43Z.json',
    '155931010632_ip-10-50-253-48_339f744979e97b13_2026-02-17T08-16-47Z.json',
    '155931010632_ip-10-50-253-8._fb4c8f7d42b6d0dc_2026-02-17T08-16-47Z.json',
    '202598902433_ip-10-45-12-137_4db17c9eaf183089_2026-02-17T08-16-42Z.json',
    '202598902433_ip-10-45-12-197_3f33a900c57a948e_2026-02-17T08-16-42Z.json',
    '202598902433_ip-10-45-12-228_0fc129eac5d5d5b2_2026-02-17T08-16-42Z.json',
    '373799569813_ip-10-247-10-16_47252e592ba8fe79_2026-02-17T08-16-36Z.json',
    '373799569813_ip-10-247-9-110_54540ed713498f55_2026-02-17T08-16-40Z.json',
    '379749588988_ip-10-53-64-103_8204f7f9f13b8295_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-105_a9edc52bb94e9713_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-106_bc3e4a12a9e8b8bb_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-124_ba0e56ab6efec5a0_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-125_28d3c1f42ffc7c68_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-159_ff338e1f02f62c17_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-160_a69a2bfff6a99bbc_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-161_5ce16ad4b1b24a0f_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-189_a60db460f3a97fa0_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-233_9a3de423dceb1ab4_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-234_b0ba4e15ad6cb4bd_2026-02-17T08-16-55Z.json',
    '379749588988_ip-10-53-64-73._f2c4f0dfd9d2cd86_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-76._f68d0e60ec82ab90_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-82._4fb03dbbc1f17af6_2026-02-17T08-16-54Z.json',
    '379749588988_ip-10-53-64-84._6a84f74b41e9e017_2026-02-17T08-16-54Z.json',
    '541136478928_ip-172-20-100-1_1a5b88191e2e88ab_2026-02-17T08-16-48Z.json',
    '541136478928_ip-172-20-100-1_20d9a3b34ea7f74f_2026-02-17T08-16-48Z.json',
    '541136478928_ip-172-20-100-1_70c5b5af97a89580_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-1_759f91fb4a2ddad9_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-1_7fcc3f05deef0ac9_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-1_8e7ec0b9a0ccc66c_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-2_1555df79dc40aeb7_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-4_ba0f1b0eea3d94f6_2026-02-17T08-16-49Z.json',
    '541136478928_ip-172-20-100-6_6f8d55d8ac74e1fb_2026-02-17T08-16-49Z.json',
    '988398044906_ip-10-45-37-20._e6caef828a5fb710_2026-02-17T08-16-45Z.json',
    '988398044906_ip-10-45-38-1.a_d4ec269a9065e653_2026-02-17T08-16-45Z.json',
    '988398044906_ip-10-45-38-239_5db7c004a5267511_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-38-244_b84832e1cdf239f5_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-38-73._199c6b4155bbfd86_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-130_ed9fd29ff941202f_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-147_29a6ba89af2bf2e9_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-194_e0f7ecb9a5ac9f01_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-206_f8ec7f5a6a74fde9_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-60._bc6cac1a40aae4dd_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-73._5e460ad433bd491e_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-77._5f2b2be24f96b2f9_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-78._f38f4b20f13ac12e_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-79._d8ac52b3af489a7f_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-82._6d2de35add1f1bfc_2026-02-17T08-16-46Z.json',
    '988398044906_ip-10-45-39-96._f89a8de36bbb3d37_2026-02-17T08-16-46Z.json',
    'sbom_i-0760d2e65db03_2bde4534936a69fa_2026-02-17T08-16-21Z.json',
]

# Scan folder to find filepaths
file_paths = {}
for root, dirs, files in os.walk('Host'):
    for f in files:
        if f.endswith('.json'):
            file_paths[f] = os.path.join(root, f)

# Validate each failed SBOM
results = []
print("Validating failed SBOMs...")
print("=" * 80)

for filename in failed_filenames:
    filepath = file_paths.get(filename)
    if not filepath:
        results.append({
            'filename': filename, 
            'error': 'File not found', 
            'account': '',
            'ip': '',
            'tags': '',
            'total_components': 0,
            'unique_components': 0,
            'duplicate_count': 0,
            'top_duplicates': ''
        })
        continue
    
    parts = filename.split('_')
    acc = parts[0] if parts else ''
    ip = parts[1].rstrip('.') if len(parts) > 1 else ''
    acc_tags = tags_map.get(acc, [])
    all_tags = ', '.join([acc] + acc_tags) if acc.isdigit() else ''
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        components = data.get('components', [])
        
        # Find duplicate component names
        names = [c.get('name', '') for c in components]
        name_counts = Counter(names)
        duplicates = [(name, count) for name, count in name_counts.items() if count > 1]
        duplicates.sort(key=lambda x: -x[1])  # Sort by count descending
        
        # Top 5 duplicates
        top_dupes = duplicates[:5]
        dupe_str = '; '.join([f'{name} ({count}x)' for name, count in top_dupes])
        
        dup_count = len(names) - len(set(names))
        
        results.append({
            'filename': filename,
            'filepath': filepath,
            'account': acc,
            'ip': ip,
            'tags': all_tags,
            'total_components': len(names),
            'unique_components': len(set(names)),
            'duplicate_count': dup_count,
            'top_duplicates': dupe_str,
            'error': 'Duplicate components'
        })
        
        print(f"\n{filename}")
        print(f"  Account: {acc} | IP: {ip}")
        print(f"  Total: {len(names)} | Unique: {len(set(names))} | Duplicates: {dup_count}")
        print(f"  Top duplicates: {dupe_str[:100]}...")
        
    except Exception as e:
        results.append({
            'filename': filename,
            'filepath': filepath if filepath else 'N/A',
            'account': acc,
            'ip': ip,
            'tags': all_tags,
            'total_components': 0,
            'unique_components': 0,
            'duplicate_count': 0,
            'top_duplicates': '',
            'error': str(e)[:100]
        })
        print(f"\n{filename}")
        print(f"  Error: {str(e)[:100]}")

# Create Excel with validation details
print("\n" + "=" * 80)
print("Creating Excel report...")

wb = Workbook()
ws = wb.active
ws.title = 'Validation Report'

headers = ['Filename', 'Account', 'IP', 'Tags', 'Total Components', 'Unique', 'Duplicates', 'Top Duplicate Components', 'Error']
header_font = Font(bold=True, color='FFFFFF')
header_fill = PatternFill(start_color='C00000', end_color='C00000', fill_type='solid')

for col, header in enumerate(headers, 1):
    cell = ws.cell(row=1, column=col, value=header)
    cell.font = header_font
    cell.fill = header_fill
    cell.alignment = Alignment(horizontal='center')

for row_idx, r in enumerate(results, 2):
    ws.cell(row=row_idx, column=1, value=r.get('filename', ''))
    ws.cell(row=row_idx, column=2, value=r.get('account', ''))
    ws.cell(row=row_idx, column=3, value=r.get('ip', ''))
    ws.cell(row=row_idx, column=4, value=r.get('tags', ''))
    ws.cell(row=row_idx, column=5, value=r.get('total_components', 0))
    ws.cell(row=row_idx, column=6, value=r.get('unique_components', 0))
    ws.cell(row=row_idx, column=7, value=r.get('duplicate_count', 0))
    ws.cell(row=row_idx, column=8, value=r.get('top_duplicates', ''))
    ws.cell(row=row_idx, column=9, value=r.get('error', ''))

for col in ws.columns:
    max_length = 0
    column = col[0].column_letter
    for cell in col:
        try:
            if len(str(cell.value)) > max_length:
                max_length = len(str(cell.value))
        except:
            pass
    ws.column_dimensions[column].width = min(max_length + 2, 80)

wb.save('failed_sboms_validation_report.xlsx')
print(f"\nValidation report saved: failed_sboms_validation_report.xlsx")
print(f"Total failed SBOMs validated: {len(results)}")
