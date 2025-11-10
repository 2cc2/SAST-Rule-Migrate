import os
import csv

def find_python_files(directory):
    """
    递归查找目录下所有文件名中包含 'python' 的文件。
    
    :param directory: 要搜索的目录路径
    :return: 包含 'python' 的文件路径列表
    """
    result = []
    for root, _, files in os.walk(directory):
        for file in files:
            result.append(os.path.join(root, file))
    return result

if __name__ == "__main__":
    # 指定要搜索的目录
    search_dir = "/home/cbb/codeql"
    
    # 查找文件
    python_files = find_python_files(search_dir)
    
    # 按字典序排序
    python_files.sort()
    
    # 输出文件路径
    output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/codeql.csv"
    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["文件路径"])  # 写入表头
        for file in python_files:
            writer.writerow([file])
    
    # 打印结果
    if python_files:
        print(f"找到 {len(python_files)} 个文件，结果已按字典序排序：")
        for file in python_files:
            print(file)
    else:
        print("未找到文件。")