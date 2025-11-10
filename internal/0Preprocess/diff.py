import os
import hashlib
import json
import difflib

def calculate_file_hash(file_path):
    """计算文件的哈希值"""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
        return None

def get_all_files_with_relative_paths(folder):
    """递归获取文件夹中所有文件的相对路径"""
    all_files = {}
    for root, _, files in os.walk(folder):
        for file in files:
            relative_path = os.path.relpath(os.path.join(root, file), folder)
            all_files[relative_path] = os.path.join(root, file)
    return all_files

def extract_differences(file1_path, file2_path):
    """提取两个文件内容的不同部分"""
    with open(file1_path, 'r', encoding='utf-8') as f1, open(file2_path, 'r', encoding='utf-8') as f2:
        content1 = f1.readlines()
        content2 = f2.readlines()
        diff = list(difflib.unified_diff(content1, content2, lineterm=''))
    return diff

def compare_files_in_folders(folder1, folder2, output_json):
    """递归比较两个文件夹中具有相同相对路径的文件内容，并保存不一致的部分到 JSON 文件"""
    folder1_files = get_all_files_with_relative_paths(folder1)
    folder2_files = get_all_files_with_relative_paths(folder2)
    
    common_files = set(folder1_files.keys()) & set(folder2_files.keys())  # 找到两个文件夹中相同相对路径的文件

    if not common_files:
        print("两个文件夹中没有相同相对路径的文件。")
        return

    differences = []

    for relative_path in common_files:
        file1_path = folder1_files[relative_path]
        file2_path = folder2_files[relative_path]

        hash1 = calculate_file_hash(file1_path)
        hash2 = calculate_file_hash(file2_path)

        if hash1 != hash2:
            print(f"文件 {relative_path} 的内容不一致。")
            diff = extract_differences(file1_path, file2_path)
            differences.append({
                "file": relative_path,
                "differences": diff
            })

    # 将不一致的内容保存为 JSON 文件
    if differences:
        with open(output_json, 'w', encoding='utf-8') as json_file:
            json.dump(differences, json_file, indent=4, ensure_ascii=False)
        print(f"不一致的内容已保存到 {output_json}")
    else:
        print("所有文件内容一致，无需保存 JSON。")

if __name__ == "__main__":
    folder1 = "/home/cbb/.codeql/packages/codeql/java-all/7.7.2/semmle"
    folder2 = "/home/cbb/codeql/java/ql/lib/semmle"
    output_json = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/differences.json"
    compare_files_in_folders(folder1, folder2, output_json)