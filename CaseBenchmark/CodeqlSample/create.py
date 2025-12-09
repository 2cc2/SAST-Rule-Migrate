import os
import json

# === 配置 ===
JSON_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_examples.json"
TEMP_DIR = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/temp"

# 读取 JSON 文件
with open(JSON_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# 确保 temp 文件夹存在
os.makedirs(TEMP_DIR, exist_ok=True)

# 遍历所有 Python 语言相关的项
if "python" not in data:
    print("未找到与 Python 相关的项")
    exit(1)

for key, target_item in data["python"].items():
    # 遍历 examples 并写入 samples
    for example in target_item["examples"]:
        for sample in example["samples"]:
            src = sample["src"]
            code = sample["code"]

            # 确定输出文件名
            if src:
                filename = os.path.basename(src)
            else:
                filename = "unknown_sample.txt"

            output_path = os.path.join(TEMP_DIR, filename)

            # 写入文件
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(code)

            print(f"✅ 写入样例文件: {output_path}")