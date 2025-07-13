import pandas as pd

# 你的主表和另一个表的路径
main_file = './data/cve_detail_filtered_all.xlsx'
other_file = './data/网络硬件设备安全知识库.xlsx'  # 请替换为实际文件名
output_file = './data/T1734628_知识库构建_第二轮.xlsx'

# 读取 main_file 所有 sheet
main_sheets = pd.read_excel(main_file, sheet_name=None)
main_df = pd.concat(main_sheets.values(), ignore_index=True)

# 读取 other_file 的第一个 sheet
other_df = pd.read_excel(other_file)  # 默认第一个sheet

# 以CVE编号为键合并，编号冲突时以主表为准
cve_col = 'CVE编号'

# 先将other_df中不在main_df的CVE编号筛选出来
other_only = other_df[~other_df[cve_col].isin(main_df[cve_col])]
# 合并
merged = pd.concat([main_df, other_only], ignore_index=True)

# 按CVE编号排序（假设格式为CVE-YYYY-NNNNN）
def cve_sort_key(x):
    try:
        parts = x.split('-')
        return (int(parts[1]), int(parts[2]))
    except Exception:
        return (0, 0)

# 用辅助列排序，避免 linter 错误
merged['_cve_sort'] = merged[cve_col].apply(cve_sort_key)
merged = merged.sort_values(by='_cve_sort')
merged = merged.reset_index(drop=True)
merged['序号'] = merged.index + 1
merged = merged.drop(columns=['_cve_sort'])

merged.to_excel(output_file, index=False)
print(f'已合并并排序输出到 {output_file}') 