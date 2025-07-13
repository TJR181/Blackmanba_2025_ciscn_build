import os
import json
from tencentcloud.common import credential
from Tools import get_cve, cve_detail, final_Excel

CONFIG = {
    "start_year": 2020,
    "end_year": 2025,
    "data_dir": "./data",
    "result_dir": "./result/",
    "tencent_ak": "你的腾讯云AK",
    "tencent_sk": "你的腾讯云SK",
    "max_workers": 20,
    "enable_translation": False,  # ✅ 是否开启翻译
    "keyword_config_file": "./config.json",  # ✅ 关键词配置文件路径
}


def load_keywords_from_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("keywords", [])
    except Exception as e:
        print(f"❌ 无法读取关键词配置文件：{e}")
        return []


def main():
    os.makedirs(CONFIG["data_dir"], exist_ok=True)
    os.makedirs(CONFIG["result_dir"], exist_ok=True)

    keywords_config = load_keywords_from_file(CONFIG["keyword_config_file"])
    if not keywords_config:
        print("❌ 未加载到任何关键词，程序终止。")
        return

    if CONFIG["enable_translation"]:
        cred = credential.Credential(CONFIG["tencent_ak"], CONFIG["tencent_sk"])
        translate_func = lambda text: cve_detail.translate_tencent_with_cred(text, cred)
    else:
        translate_func = None

    # 遍历关键词组合
    total = sum(len(item.get("keywords", [])) for item in keywords_config)
    count = 0

    for item in keywords_config:
        device_type = item["device_type"]
        keyword_list = item.get("keywords", [])
        for keyword in keyword_list:
            count += 1
            print(f"\n🔍 正在请求 CVE ID 页面（{count}/{total}）：[{keyword}]...")
            get_cve.get_and_save_cve_ids(
            device_type=device_type,
            keyword=keyword,
            start_year=CONFIG["start_year"],
            end_year=CONFIG["end_year"],
            output_dir=CONFIG["data_dir"],
            max_workers=CONFIG["max_workers"]
        )

    # 抓取详情
    cve_detail.process_all_txt_files(
        data_dir=CONFIG["data_dir"],
        translate_func=translate_func,
        max_workers=CONFIG["max_workers"],
    )

    final_Excel.jsons_to_excel(
        data_dir=CONFIG["data_dir"],
        result_dir=CONFIG["result_dir"],
    )


if __name__ == "__main__":
    main()
