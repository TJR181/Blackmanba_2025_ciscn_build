import os
import requests
import re
import time
import concurrent.futures
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm


def requests_retry_session(
    retries=3,
    backoff_factor=1,
    status_forcelist=(500, 502, 503, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff_factor,
        allowed_methods=["GET", "POST"],
        status_forcelist=status_forcelist,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_cve_ids(keyword, start_year, end_year, sleep_seconds=5):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
    headers = {"User-Agent": "Mozilla/5.0"}
    session = requests_retry_session()

    try:
        response = session.get(url, headers=headers, timeout=(10, 20))
        response.raise_for_status()
    except Exception as e:
        print(f"❌ 请求失败 [{keyword}]：{e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    cve_pattern = re.compile(r"CVE-(\d{4})-\d+")
    cve_ids = set()

    for link in soup.find_all("a", href=True):
        text = link.text.strip()
        match = cve_pattern.match(text)
        if match:
            year = int(match.group(1))
            if start_year <= year <= end_year:
                cve_ids.add(text)

    print(f"✅ [{keyword}] 共发现 {len(cve_ids)} 条 CVE")
    time.sleep(sleep_seconds)
    return sorted(cve_ids, reverse=True)


def get_and_save_cve_ids(
    device_type, keyword, start_year, end_year, output_dir="./data", max_workers=4
):
    filename = f"{device_type}_{keyword}.txt"
    filepath = os.path.join(output_dir, filename)

    if os.path.exists(filepath):
        print(f"⚠️ 文件已存在，跳过爬取：{filepath}")
        return

    print(f"\n🔍 正在请求 CVE ID 页面 [{keyword}]...")
    cves = get_cve_ids(keyword, start_year, end_year)
    if not cves:
        print(f"⚠️ 没有找到符合条件的 CVE 编号：{device_type}_{keyword}")
        return

    os.makedirs(output_dir, exist_ok=True)

    print(f"📄 正在保存 {device_type}_{keyword} 共 {len(cves)} 条 CVE ...")
    failed = []

    def validate(cve):
        if re.match(r"CVE-\d{4}-\d+", cve):
            return cve
        else:
            failed.append(cve)
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            tqdm(
                executor.map(validate, cves),
                total=len(cves),
                desc=f"📥 验证 {device_type}/{keyword}",
                ncols=100,
            )
        )

    valid_cves = [cve for cve in results if cve]

    with open(filepath, "w", encoding="utf-8") as f:
        for idx, cve in enumerate(valid_cves, start=1):
            f.write(cve + "\n")

    print(f"\n✅ 成功写入 {len(valid_cves)} 条 CVE 到 {filepath}")
    if failed:
        print(f"❌ 有 {len(failed)} 条无效 CVE 编号未写入：{failed}")
