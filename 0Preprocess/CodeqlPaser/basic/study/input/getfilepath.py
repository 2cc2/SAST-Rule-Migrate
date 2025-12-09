import os
import csv

def find_all_files(directory):
    """
    递归查找目录下所有文件，并返回相对路径（以 codeql/ 为根目录）。
    """
    result = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 计算相对路径
            relative_path = os.path.relpath(os.path.join(root, file), directory)
            # 前缀加上 codeql/
            result.append(os.path.join("codeql", relative_path))
    return result

if __name__ == "__main__":
    # 要搜索的目录
    search_dir = "/home/cbb/codeql"
    
    # 查找所有文件
    all_files = find_all_files(search_dir)
    
    # 字典序排序
    all_files.sort()
    
    # 输出 CSV
    output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/input/codeql.csv"
    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["文件路径"])
        for file in all_files:
            writer.writerow([file])
    
    # 打印结果
    # if all_files:
    #     print(f"找到 {len(all_files)} 个文件，结果已按字典序排序：")
    #     for file in all_files:
    #         print(file)
    # else:
    #     print("未找到文件。")