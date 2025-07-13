import os
import time
import pandas as pd
from tqdm import tqdm
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed

# 读取 API Key
api_key = "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"  # 请妥善保管你的 API Key

# 初始化客户端
client = OpenAI(api_key=api_key)

TARGET_COLUMN = '漏洞描述'
OUTPUT_COLUMN = TARGET_COLUMN + '_中文'
SAVE_INTERVAL = 1000  # 每翻译多少条保存一次
MAX_WORKERS = 25

def translate_with_chatgpt(text: str, max_retries=10000, retry_delay=2) -> str:
    if not isinstance(text, str) or not text.strip():
        return ''
    prompt = (
        "请严格将以下技术漏洞描述翻译成简体中文，"
        "只输出翻译后的文本，不要包含任何额外内容、解释、引号、注释或者换行符。"
        "\n\n原文：\n"
        f"{text}"
    )
    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"❌ 第{attempt}次重试失败：{text[:50]}...，原因：{e}")
            if attempt == max_retries:
                print(f"⚠️ 达到最大重试次数，返回原文")
                return text
            time.sleep(retry_delay)

def main():
    input_file = './result/网络硬件设备安全知识库.xlsx'
    output_file = './result/网络硬件设备安全知识库_ChatGPT翻译.xlsx'

    df = pd.read_excel(input_file)

    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"❗找不到列：{TARGET_COLUMN}")

    texts = df[TARGET_COLUMN].tolist()
    results = [None] * len(texts)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {executor.submit(translate_with_chatgpt, text): idx for idx, text in enumerate(texts)}

        completed = 0
        for future in tqdm(as_completed(future_to_idx), total=len(texts), desc="ChatGPT 翻译中"):
            idx = future_to_idx[future]
            try:
                translation = future.result()
            except Exception as e:
                print(f"❌ 任务异常：索引 {idx}，原因：{e}")
                translation = texts[idx]
            results[idx] = translation
            completed += 1

            print(f"\n【原文】{texts[idx]}\n【翻译】{translation}\n")

            # 每 SAVE_INTERVAL 条保存一次
            if completed % SAVE_INTERVAL == 0:
                df[OUTPUT_COLUMN] = results
                partial_output = output_file.replace('.xlsx', f'_part_{completed}.xlsx')
                df.to_excel(partial_output, index=False)
                print(f"📝 已保存中间结果到：{partial_output}")

    # 最终保存完整文件
    df[OUTPUT_COLUMN] = results
    df.to_excel(output_file, index=False)
    print(f"\n✅ 翻译完成，保存到：{output_file}")

if __name__ == "__main__":
    main()
