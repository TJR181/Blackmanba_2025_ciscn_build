import concurrent.futures
import requests
import json
import os
import time
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm


def get_session_with_retries(retries=5, backoff_factor=1):
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def extract_cve_info(cve_id, device_type="unknown", translate_func=None, session=None):
    session = session or get_session_with_retries()
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"请求 CVE 数据失败: {e}")

    data = response.json()

    cna = data.get("containers", {}).get("cna", {})
    metadata = data.get("cveMetadata", {})

    affected = cna.get("affected", [])
    vendor = affected[0].get("vendor", "") if affected else ""
    product = affected[0].get("product", "") if affected else ""
    versions_raw = (
        [v.get("version", "") for v in affected[0].get("versions", [])]
        if affected
        else []
    )
    versions = sorted(set([v.strip() for v in versions_raw if v.strip()])) or [
        "所有未更新补丁的相关版本"
    ]

    description_en = next(
        (d.get("value") for d in cna.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    description_zh = (
        translate_func(description_en)
        if translate_func and description_en
        else description_en
    )

    attack_vector = "N/A"
    metrics = cna.get("metrics", [])
    if metrics:
        for metric in metrics:
            for key in metric:
                if key.startswith("cvss") and isinstance(metric[key], dict):
                    av = metric[key].get("attackVector")
                    if av:
                        attack_vector = av
                        break
                    else:
                        attack_vector = "Network"
            if attack_vector != "N/A":
                break
    attack_vector_zh = (
        translate_func(attack_vector)
        if translate_func and attack_vector != "N/A"
        else attack_vector
    )

    patch_links = [
        ref.get("url")
        for ref in cna.get("references", [])
        if "url" in ref and not ref.get("url", "").startswith("https://vuldb.com")
    ] or ["无官方补丁，建议联系厂商或及时更新系统"]

    raw_date = metadata.get("datePublished", "")
    try:
        formatted_date = datetime.fromisoformat(raw_date.replace("Z", "")).strftime(
            "%Y年%m月%d日"
        )
    except:
        formatted_date = raw_date

    return {
        "设备品牌": vendor,
        "设备类型": device_type,
        "产品型号": product,
        "CVE编号": metadata.get("cveId", ""),
        "漏洞描述": description_zh,
        "攻击向量": attack_vector_zh,
        "厂商补丁链接": patch_links,
        "受影响版本": versions,
        "公开日期": formatted_date,
    }


def load_existing_cves(json_file):
    if not os.path.exists(json_file):
        return [], set()
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        existing_ids = {item.get("CVE编号") for item in data if item.get("CVE编号")}
    return data, existing_ids


def load_cve_ids_from_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def process_all_txt_files(data_dir="./data", translate_func=None, max_workers=5):
    if not os.path.exists(data_dir):
        print(f"❌ 目录 {data_dir} 不存在！")
        return

    txt_files = [f for f in os.listdir(data_dir) if f.endswith(".txt") and "_" in f]
    if not txt_files:
        print(f"❌ {data_dir} 目录下未找到符合格式的 .txt 文件")
        return

    session = get_session_with_retries()

    for index, txt_file in enumerate(txt_files, start=1):
        try:
            device_type, keyword_with_ext = txt_file.split("_", 1)
            keyword = keyword_with_ext.rsplit(".", 1)[0]
        except Exception as e:
            print(f"⚠️ 文件名解析失败 {txt_file}，跳过。错误: {e}")
            continue

        print(
            f"\n📄 正在处理文件（{index}/{len(txt_files)}）：{txt_file} （类型：{device_type} / 关键词：{keyword}）"
        )

        txt_path = os.path.join(data_dir, txt_file)
        cve_list = load_cve_ids_from_file(txt_path)

        json_path = os.path.join(data_dir, f"{device_type}_{keyword}.json")
        output, existing_ids = load_existing_cves(json_path)

        new_cve_ids = [cve for cve in cve_list if cve not in existing_ids]

        def fetch_with_retries(cve_id, max_retries=3):
            for attempt in range(max_retries):
                try:
                    time.sleep(1)
                    return extract_cve_info(
                        cve_id,
                        device_type=device_type,
                        translate_func=translate_func,
                        session=session,
                    )
                except Exception as e:
                    if attempt == max_retries - 1:
                        print(f"⚠️ 获取 {cve_id} 失败（尝试 {attempt + 1} 次）：{e}")
                        return None
                    time.sleep(2)

        results = list(
            tqdm(
                concurrent.futures.ThreadPoolExecutor(max_workers=max_workers).map(
                    fetch_with_retries, new_cve_ids
                ),
                total=len(new_cve_ids),
                desc=f"📥 获取 {device_type}_{keyword} CVE 详情",
                ncols=100,
            )
        )

        new_results = [r for r in results if r]
        output.extend(new_results)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(
            f"✅ {device_type}_{keyword} 新增 {len(new_results)} 条数据写入 {json_path}"
        )

        if len(new_results) < len(new_cve_ids):
            print(f"❌ 共失败 {len(new_cve_ids) - len(new_results)} 条")
