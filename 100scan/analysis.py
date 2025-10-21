import os
import csv

def clean_csv_files_in_folder(folder_path, output_folder_path):
    """
    遍历文件夹中的所有 .csv 文件，删除含 /test/ 的行，并将结果保存到另一个文件夹中。
    
    Args:
        folder_path (str): 源文件夹路径。
        output_folder_path (str): 目标文件夹路径。
    """
    # 确保目标文件夹存在
    os.makedirs(output_folder_path, exist_ok=True)
    
    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            file_path = os.path.join(folder_path, filename)
            output_file_path = os.path.join(output_folder_path, filename)
            print(f"正在处理文件: {file_path}")
            
            # 读取并过滤文件内容
            with open(file_path, mode="r", encoding="utf-8") as infile:
                reader = csv.DictReader(infile)
                rows = [row for row in reader if "/test/" not in row["filename"]]
            
            # 将过滤后的内容写入目标文件夹
            with open(output_file_path, mode="w", encoding="utf-8", newline="") as outfile:
                writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            
            print(f"文件已处理并保存到: {output_file_path}")

# 指定源文件夹路径和目标文件夹路径
folder_path = "/Users/djoker/Desktop/CTGA/demo/100scan/data/bandit_results"  # 替换为你的源文件夹路径
output_folder_path = "/Users/djoker/Desktop/CTGA/demo/100scan/data/filtered_results"  # 替换为你的目标文件夹路径

# 调用函数清理文件夹中的 CSV 文件
clean_csv_files_in_folder(folder_path, output_folder_path)