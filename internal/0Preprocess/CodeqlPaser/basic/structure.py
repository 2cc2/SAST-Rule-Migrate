import os
import json

def scan_directory(directory):
    """
    递归扫描目录，返回嵌套字典表示的项目结构。
    """
    project_structure = {}
    for entry in os.scandir(directory):
        if entry.is_dir():
            # 如果是文件夹，递归调用
            project_structure[entry.name] = scan_directory(entry.path)
        elif entry.is_file():
            # 如果是文件，标记为 "file"
            project_structure[entry.name] = ""
    return project_structure

def save_structure_to_json(structure, output_file):
    """
    将项目结构保存为 JSON 文件。
    """
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(structure, f, indent=4, ensure_ascii=False)

def scan_and_copy_structure(source_directory, target_directory):
    """
    递归扫描源目录并在目标位置复制目录结构（不复制文件内容）。
    """
    for entry in os.scandir(source_directory):
        target_path = os.path.join(target_directory, entry.name)
        if entry.is_dir():
            # 如果是文件夹，创建对应的目标文件夹并递归处理
            os.makedirs(target_path, exist_ok=True)
            scan_and_copy_structure(entry.path, target_path)
        elif entry.is_file():
            # 如果是文件，创建一个空文件
            open(target_path, 'w').close()

if __name__ == "__main__":
    # 要扫描的目录
    root_directory = "/home/cbb/codeql"
    # 扫描目录
    project_structure = scan_directory(root_directory)
    # 保存为 JSON 文件
    save_structure_to_json(project_structure, "/home/cbb/SAST-Rule-Migrate/Pretools/sourcesink/output/project_structure.json")
    print("✅ 项目结构已保存到 project_structure.json")

    # 源目录
    source_directory = "/home/cbb/codeql"
    # 目标目录
    target_directory = "/home/cbb/SAST-Rule-Migrate/Pretools/structure"

    # 创建目标目录
    os.makedirs(target_directory, exist_ok=True)

    # 扫描并复制目录结构
    scan_and_copy_structure(source_directory, target_directory)
    print(f"✅ 目录结构已复制到 {target_directory}")