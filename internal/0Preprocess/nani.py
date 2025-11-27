import json
import os
language="java"
# 文件夹路径
dir_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{language}_missed_modules/"

# 保存统计结果的路径
output_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{language}_missed_modules_summary.json"

# 初始化结果列表
results = []

# 遍历目录下所有 JSON 文件
for filename in os.listdir(dir_path):
    if filename.endswith(".json"):
        file_path = os.path.join(dir_path, filename)
        
        # 读取 JSON 文件
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        # 提取 file_path 和 missed_modules
        file_path_value = data.get("file_path", "未知文件路径")
        missed_modules = data.get("missed_modules", [])
        
        # 统计 missed_modules 的数量
        missed_count = len(missed_modules)
        
        # 将结果追加到 results 列表
        results.append({
            "file_path": file_path_value,
            "missed_count": missed_count
        })

# 保存结果到 JSON 文件
with open(output_path, "w", encoding="utf-8") as output_file:
    json.dump(results, output_file, indent=4, ensure_ascii=False)

print(f"统计结果已保存到 {output_path}")