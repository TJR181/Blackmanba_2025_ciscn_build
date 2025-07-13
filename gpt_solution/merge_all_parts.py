import os
import pandas as pd

# 合并当前目录下所有part表
all_parts = [f for f in os.listdir('./data') if f.startswith('cve_detail_filtered_part') and f.endswith('.xlsx')]
all_parts.sort()

if not all_parts:
    print('未找到分表，无需合并。')
    exit(0)

dfs = [pd.read_excel(os.path.join('./data', f)) for f in all_parts]
df_all = pd.concat(dfs, ignore_index=True)
total_file = './data/cve_detail_filtered_all.xlsx'
df_all.to_excel(total_file, index=False)
print(f'已生成总表 {total_file}') 