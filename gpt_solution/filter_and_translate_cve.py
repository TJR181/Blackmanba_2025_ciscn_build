import os
import pandas as pd
import openai
from tqdm import tqdm
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 用户需在此处填写自己的OpenAI API Key
openai.api_key = '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'
MODEL_NAME = 'gpt-4.1-mini'

input_file = os.path.join('data', 'cve_detail.xlsx')
# output_file = os.path.join('data', 'cve_detail_filtered.xlsx') # 不再用单一输出文件

# 需要处理的字段
DEVICE_TYPE_COL = '设备类型'
VENDOR_COL = '设备品牌'
ATTACK_VECTOR_COL = '攻击向量'
DESC_COL = '漏洞描述'

# 断点续传参数
start_idx = 70000
start_batch = 14

# 读取表格
try:
    df = pd.read_excel(input_file, sheet_name=0)
except Exception as e:
    print(f'读取表格失败: {e}')
    exit(1)

system_prompt = (
    "你是网络安全领域的专家。请判断下述CVE条目是否属于硬件设备漏洞或车联网设备漏洞。"
    "如果是，请将设备类型、设备品牌（英文名）、攻击向量（翻译成中文，如无则根据简介生成）和漏洞描述翻译为简体中文，并以如下JSON格式返回："
    '{"is_hardware_or_vehicular": true, "device_type_zh": "...", "vendor": "...", "attack_vector_zh": "...", "desc_zh": "..."}'
    "请确保 vendor 字段输出为推断出的品牌英文名（如‘Cisco’、‘Hikvision’、‘GM’等），不要翻译为中文。如果无法判断品牌，请输出‘Unknown’。"
    "请确保 device_type_zh 字段输出为具体的设备名称（如‘路由器’、‘交换机’、‘摄像头’、‘汽车网关’等），不要用‘硬件设备’、‘车联网设备’等泛泛词汇。"
    "请确保 attack_vector_zh 字段为攻击向量的简体中文翻译，如果原始数据没有攻击向量，请根据漏洞简介合理生成。"
    "如果不是，请返回：{\"is_hardware_or_vehicular\": false}"
)

rows_to_keep = []
translated_device_types = []
translated_vendors = []
translated_attack_vectors = []
translated_descs = []
rows_lock = threading.Lock()

# 初始化新版openai client
client = openai.OpenAI(api_key=openai.api_key)

# 分批写入函数
def write_batch(batch_idx, idx_list, dev_types, vendors, attack_vectors, descs):
    filtered_df = df.loc[idx_list].copy()
    filtered_df[DEVICE_TYPE_COL] = dev_types
    filtered_df[VENDOR_COL] = vendors
    filtered_df[ATTACK_VECTOR_COL] = attack_vectors
    filtered_df[DESC_COL] = descs
    output_file = os.path.join('data', f'cve_detail_filtered_part{batch_idx}.xlsx')
    filtered_df.to_excel(output_file, index=False)
    print(f'已写入 {output_file}')

# 单条处理函数，带重试
def process_row(idx, device_type, vendor, attack_vector, desc):
    user_prompt = f"设备类型: {device_type}\n设备品牌: {vendor}\n攻击向量: {attack_vector}\n漏洞描述: {desc}"
    for attempt in range(10000):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=512
            )
            content = response.choices[0].message.content
            import json
            if isinstance(content, str):
                result = json.loads(content)
                tqdm.write(f'第{idx+1}行结果: {result}')
                if result.get('is_hardware_or_vehicular'):
                    with rows_lock:
                        rows_to_keep.append(idx)
                        translated_device_types.append(result.get('device_type_zh', device_type))
                        if not vendor or str(vendor).strip() == '':
                            translated_vendors.append(result.get('vendor', 'Unknown'))
                        else:
                            translated_vendors.append(vendor)
                        translated_attack_vectors.append(result.get('attack_vector_zh', attack_vector))
                        translated_descs.append(result.get('desc_zh', desc))
            return
        except Exception as e:
            print(f'第{idx+1}行第{attempt+1}次重试: {e}')
            time.sleep(2)
    print(f'第{idx+1}行重试10000次仍失败，跳过')

# 多线程并发处理
with ThreadPoolExecutor(max_workers=150) as executor:
    futures = []
    for idx, row in df.iterrows():
        if idx < start_idx:
            continue
        device_type = str(row.get(DEVICE_TYPE_COL, ''))
        vendor = str(row.get(VENDOR_COL, ''))
        attack_vector = str(row.get(ATTACK_VECTOR_COL, ''))
        desc = str(row.get(DESC_COL, ''))
        futures.append(executor.submit(process_row, idx, device_type, vendor, attack_vector, desc))
    for _ in tqdm(as_completed(futures), total=len(futures)):
        pass

# 主线程统一分批写入和清理，避免空表
batch_idx = start_batch
while len(rows_to_keep) >= 1000:
    write_batch(batch_idx, rows_to_keep[:1000],
                translated_device_types[:1000],
                translated_vendors[:1000],
                translated_attack_vectors[:1000],
                translated_descs[:1000])
    del rows_to_keep[:1000]
    del translated_device_types[:1000]
    del translated_vendors[:1000]
    del translated_attack_vectors[:1000]
    del translated_descs[:1000]
    batch_idx += 1

# 写入最后一批（不足1000条）
if len(rows_to_keep) > 0:
    write_batch(batch_idx, rows_to_keep,
                translated_device_types,
                translated_vendors,
                translated_attack_vectors,
                translated_descs)

print('全部处理完成！')