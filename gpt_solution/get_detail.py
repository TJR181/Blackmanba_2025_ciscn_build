import os
import json
import pandas as pd
from datetime import datetime

# 路径设置
cve_list_file = os.path.join('data', 'all_public_cve.txt')
cves_dir = os.path.join('data', 'cves')
output_xlsx = os.path.join('data', 'cve_detail.xlsx')

# 表头
columns = [
    '序号', '设备品牌', '设备类型', '产品型号', 'CVE编号',
    '漏洞描述', '攻击向量', '厂商补丁链接', '受影响版本', '公开日期'
]

def extract_from_json(cve_id):
    # 路径推断
    year = cve_id.split('-')[1]
    num = cve_id.split('-')[2]
    num_dir = num[:-3] + 'xxx' if len(num) > 3 else num[0] + 'xxx'
    json_path = os.path.join(cves_dir, year, num_dir, f'{cve_id}.json')
    if not os.path.exists(json_path):
        return None
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # 设备品牌/类型/型号/受影响版本
    brand, dev_type, model, affected_version = '', '', '', ''
    try:
        affected = data['containers']['cna']['affected'][0]
        brand = affected.get('vendor', '')
        model = affected.get('product', '')
        versions = affected.get('versions', [])
        if versions and isinstance(versions, list):
            affected_version = '，'.join([v.get('version', '') for v in versions if v.get('version', '')])
    except Exception:
        pass
    # 漏洞描述
    desc = ''
    try:
        desc = data['containers']['cna']['descriptions'][0]['value']
    except Exception:
        try:
            desc = data['containers']['cna']['x_legacyV4Record']['description']['description_data'][0]['value']
        except Exception:
            pass
    # 攻击向量
    attack_vector = ''
    try:
        metrics = data['containers']['cna'].get('metrics', [])
        for metric in metrics:
            for key in ['cvssV3_1', 'cvssV3_0']:
                if key in metric and 'attackVector' in metric[key]:
                    attack_vector = metric[key]['attackVector']
                    break
            if attack_vector:
                break
        # 若未找到，再尝试problemTypes
        if not attack_vector:
            pt = data['containers']['cna']['problemTypes'][0]['descriptions'][0].get('description', '')
            if pt and pt != 'n/a':
                attack_vector = pt
    except Exception:
        pass
    # 厂商补丁链接
    patch_url = ''
    try:
        refs = data['containers']['cna'].get('references', [])
        if refs:
            patch_url = refs[0].get('url', '')
    except Exception:
        pass
    # 公开日期
    pub_date = ''
    try:
        pub_date = data['cveMetadata'].get('datePublished', '')
        if pub_date:
            try:
                pub_date = datetime.strptime(pub_date[:10], '%Y-%m-%d').strftime('%Y年%m月%d日')
            except Exception:
                pass
    except Exception:
        pass
    return [brand, dev_type, model, cve_id, desc, attack_vector, patch_url, affected_version, pub_date]

def main():
    rows = []
    with open(cve_list_file, 'r', encoding='utf-8') as f:
        cve_ids = [line.strip() for line in f if line.strip()]
    for idx, cve_id in enumerate(cve_ids, 1):
        info = extract_from_json(cve_id)
        if info is None:
            info = [''] * (len(columns) - 1)
            info.insert(3, cve_id)  # 只填CVE编号
        row = [idx] + info
        rows.append(row)
        if idx % 100 == 0:
            print(f'已处理{idx}条...')
    df = pd.DataFrame(rows, columns=pd.Index(columns))
    df.to_excel(output_xlsx, index=False, sheet_name='sheet1')
    print(f'已生成 {output_xlsx}')

if __name__ == '__main__':
    main() 