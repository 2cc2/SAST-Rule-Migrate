import os
import csv
import json
from summary import process_file

# 配置路径
CSV_FILE = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/filelist/shared.csv"
BASE_DIR = "/home/cbb/"
OUTPUT_FILE = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/shared_summary.json"

def read_csv(file_path):
    """读取 CSV 文件并返回相对路径列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # 跳过表头
            return [row[0] for row in reader if row]
    except Exception as e:
        print(f"❌ 无法读取 CSV 文件：{file_path}\n错误：{e}")
        return []

def summarize_files(relative_paths, base_dir):
    """对文件进行总结"""
    results = []
    for rel_path in relative_paths:
        abs_path = os.path.join(base_dir, rel_path)
        if os.path.exists(abs_path):
            print(f"🧩 正在处理文件：{abs_path}")
            summary = process_file(abs_path)
            if summary:
                results.append(summary)
        else:
            print(f"⚠️ 文件不存在：{abs_path}")
    return results

def save_results(results, output_file):
    """保存总结结果到 JSON 文件"""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"✅ 总结结果已保存到 {output_file}")
    except Exception as e:
        print(f"❌ 无法保存结果到文件：{output_file}\n错误：{e}")

if __name__ == "__main__":
    # 读取 CSV 文件
    relative_paths = read_csv(CSV_FILE)

    # 对文件进行总结
    summaries = summarize_files(relative_paths, BASE_DIR)

    # 保存结果
    save_results(summaries, OUTPUT_FILE)