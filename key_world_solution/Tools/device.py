import time
import pandas as pd
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置你的 OpenAI API key
api_key = "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"
client = OpenAI(api_key=api_key)

# 输入输出文件
input_file = './input.xlsx'
output_file_template = './result/output_with_device_type_part_{}.xlsx'

# 推理函数
def infer_device_type(brand: str, model: str, description: str, max_retries=10, retry_delay=2) -> str:
    prompt = (
        f"请从产品信息中判断其所属的设备类型，只返回设备类型名称，例如："
        f"例如：路由器、防火墙、交换机等等。\n\n"
        f"品牌：{brand}\n型号：{model}\n漏洞描述：{description}\n\n"
        f"只返回设备类型名称，不要多余解释或引号。\n 请使用简体中文回答。\n\n"
    )
    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"调用失败 第{attempt}次，原因：{e}")
            if attempt == max_retries:
                print("达到最大重试次数，返回未知设备类型")
                return "未知设备类型"
            time.sleep(retry_delay)

def main():
    df = pd.read_excel(input_file)
    results = [None] * len(df)

    max_workers = 40
    batch_size = 1000

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for idx, row in df.iterrows():
            brand = str(row.get('设备品牌', '')).strip()
            model = str(row.get('产品型号', '')).strip()
            desc = str(row.get('漏洞描述', '')).strip()
            futures[executor.submit(infer_device_type, brand, model, desc)] = idx

        completed = 0
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
            except Exception as e:
                print(f"索引{idx}调用异常：{e}")
                result = "未知设备类型"

            results[idx] = result
            print(f"[{idx}] 推理结果：{result}")

            completed += 1
            if completed % batch_size == 0:
                df['AI识别设备类型'] = results
                batch_output_file = output_file_template.format(completed)
                df.to_excel(batch_output_file, index=False)
                print(f"已处理 {completed} 条记录，保存为 {batch_output_file}")

    df['AI识别设备类型'] = results
    df.to_excel(output_file_template.format("final"), index=False)
    print(f"\n✅ 所有设备类型识别完成，最终结果已保存到 {output_file_template.format('final')}")

if __name__ == "__main__":
    main()
