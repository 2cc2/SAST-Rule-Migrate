import os
import json

def fix_json_files_in_folder(folder_path):
    """
    批量处理文件夹下的 JSON 文件，修复格式问题并保存修复后的文件。
    
    Args:
        folder_path (str): 文件夹路径。
    """
    # 遍历文件夹中的所有文件
    sum =0
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(folder_path, filename)
            print(f"正在处理文件: {file_path}")
            sum +=1
    print(f"总共处理文件数: {sum}")  
            # try:
            #     # 读取 JSON 文件内容
            #     with open(file_path, "r", encoding="utf-8") as file:
            #         content = file.read()
                
            #     # 尝试加载 JSON 数据
            #     try:
            #         data = json.loads(content)
            #     except json.JSONDecodeError:
            #         # 如果 JSON 格式有问题，尝试修复
            #         print(f"文件 {filename} 格式有问题，尝试修复...")
            #         content = content.rstrip(",")  # 去掉末尾的逗号
            #         content = content.strip()  # 去掉多余的空格
            #         data = json.loads(content)  # 再次尝试加载
                
            #     # 保存修复后的 JSON 数据到新文件
            #     fixed_file_path = os.path.join("/Users/djoker/Desktop/CTGA/demo/100scan/data/semgrep_resultss", f"{filename}")
            #     with open(fixed_file_path, "w", encoding="utf-8") as fixed_file:
            #         json.dump(data, fixed_file, indent=4, ensure_ascii=False)
            #     print(f"文件 {filename} 修复完成，已保存为 {fixed_file_path}")
            
            # except Exception as e:
            #     print(f"处理文件 {filename} 时出错: {e}")

# 指定要处理的文件夹路径
folder_path = "/Users/djoker/Desktop/CTGA/demo/100scan/data/semgrep_results"  # 替换为你的文件夹路径

# 调用函数处理文件夹中的 JSON 文件
fix_json_files_in_folder(folder_path)