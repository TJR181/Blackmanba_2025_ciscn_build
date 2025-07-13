import os
import re

# 只处理2020及以后的年份目录
year_start = 2020
cves_dir = os.path.join('data', 'cves')
output_file = os.path.join('data', 'all_public_cve.txt')

cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
all_cves = set()

for year in os.listdir(cves_dir):
    if not year.isdigit() or int(year) < year_start:
        continue
    year_path = os.path.join(cves_dir, year)
    for root, dirs, files in os.walk(year_path):
        for fname in files:
            match = cve_pattern.match(fname.replace('.json', ''))
            if match:
                all_cves.add(match.group(0))

with open(output_file, 'w', encoding='utf-8') as f:
    for cve in sorted(all_cves, key=lambda x: (int(x.split('-')[1]), int(x.split('-')[2]))):
        f.write(cve + '\n')

print(f"共收集到 {len(all_cves)} 个CVE编号，已写入 {output_file}")
