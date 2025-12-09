import csv
import json
import os
import re



def read_csv_file(file_path):
    """读取 CSV 文件并返回路径列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)  # 跳过表头
            return [row[0] for row in reader if row]  # 假设路径在第一列
    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
    except Exception as e:
        print(f"读取 CSV 文件时出错: {e}")
    return []

def extract_imports_and_modules(file_content):
    """通过正则表达式提取文件内容中的 imports 和 modules"""
    imports = re.findall(r"import\s+([\w.]+)", file_content)
    modules = re.findall(r"module\s+([\w.]+)", file_content)
    return imports, modules

def extract_classes(file_content):
    """通过正则表达式提取文件内容中的类定义"""
    classes = re.findall(r"class\s+(\w+)", file_content)
    return classes

def process_csv_data(file_paths, output_file, repo_root, class_output_file, import_output_file):
    """处理 CSV 文件中的路径，提取 imports、modules 和 classes 并保存到文件"""
    results = {}
    class_to_filepath = {}
    import_to_filepath = {}

    for relative_path in file_paths:
        absolute_path = os.path.join(repo_root, relative_path)  # 根据仓库根目录构造绝对路径
        if os.path.exists(absolute_path):
            try:
                with open(absolute_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    imports, modules = extract_imports_and_modules(content)
                    classes = extract_classes(content)

                    results[relative_path] = {
                        "absolute_path": absolute_path,
                        "imports": imports,
                        "modules": modules,
                        "classes": classes
                    }

                    # 更新类与文件路径的映射
                    for cls in classes:
                        class_to_filepath[cls] = absolute_path

                    # 更新 imports 与文件路径的映射
                    for imp in imports:
                        if imp not in import_to_filepath:
                            import_to_filepath[imp] = []
                        import_to_filepath[imp].append(absolute_path)

            except Exception as e:
                print(f"无法读取文件 {absolute_path}: {e}")
        else:
            print(f"路径不存在: {absolute_path}")

    # 保存处理结果
    os.makedirs(os.path.dirname(output_file), exist_ok=True)  # 确保输出文件夹存在
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"处理结果已保存到 {output_file}")

    # 保存类与文件路径的映射
    os.makedirs(os.path.dirname(class_output_file), exist_ok=True)
    with open(class_output_file, "w", encoding="utf-8") as f:
        json.dump(class_to_filepath, f, ensure_ascii=False, indent=2)
    print(f"类与文件路径的映射已保存到 {class_output_file}")

    # 保存 imports 与文件路径的映射
    os.makedirs(os.path.dirname(import_output_file), exist_ok=True)
    with open(import_output_file, "w", encoding="utf-8") as f:
        json.dump(import_to_filepath, f, ensure_ascii=False, indent=2)
    print(f"imports 与文件路径的映射已保存到 {import_output_file}")

def create_module_to_filepath_mapping(tree):
    """
    从扫描结果中创建 module 到 filepath 的映射

    Args:
        tree (dict): 扫描结果的树状结构

    Returns:
        dict: module 到 filepath 的映射
    """
    module_to_filepath = {}

    def traverse_tree(subtree):
        for key, value in subtree.items():
            if isinstance(value, dict):
                if "absolute_path" in value and "modules" in value:
                    for module in value["modules"]:
                        module_to_filepath[module] = value["absolute_path"]
                else:
                    traverse_tree(value)

    traverse_tree(tree)
    return module_to_filepath

def create_module_to_filepath_mapping_by_language(tree):
    """
    从扫描结果中按语言创建 module 到 filepath 的映射

    Args:
        tree (dict): 按语言组织的扫描结果树状结构

    Returns:
        dict: 每种语言的 module 到 filepath 的映射
    """
    language_to_module_mapping = {}

    for language, subtree in tree.items():
        module_to_filepath = {}

        def traverse_tree(subtree):
            for key, value in subtree.items():
                if isinstance(value, dict):
                    if "absolute_path" in value and "modules" in value:
                        for module in value["modules"]:
                            module_to_filepath[module] = value["absolute_path"]
                    else:
                        traverse_tree(value)

        traverse_tree(subtree)
        language_to_module_mapping[language] = module_to_filepath

    return language_to_module_mapping


# 主程序
if __name__ == "__main__":

    # 处理 CSV 文件
    repo_root = "/home/cbb/"  # 仓库根目录
    csv_folder = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/filelist"
    csv_output_folder = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/imports_modules_outputs"
    module_mapping_folder = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/module_mappings"
    class_mapping_folder = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/class_mappings"
    import_mapping_folder = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/import_mappings"
    languages = ["python", "java", "go", "javascript", "shared", "qlpack"]

    all_results = {}

    for language in languages:
        csv_file = f"{csv_folder}/{language}.csv"
        output_file = f"{csv_output_folder}/{language}_results.json"
        class_output_file = f"{class_mapping_folder}/{language}_class_to_filepath.json"
        import_output_file = f"{import_mapping_folder}/{language}_import_to_filepath.json"

        print(f"处理语言: {language}")
        file_paths = read_csv_file(csv_file)
        process_csv_data(file_paths, output_file, repo_root, class_output_file, import_output_file)

        # 读取处理结果
        with open(output_file, "r", encoding="utf-8") as f:
            all_results[language] = json.load(f)

    # 创建按语言的 module 到 filepath 的映射
    language_to_module_mapping = create_module_to_filepath_mapping_by_language(all_results)

    # 保存每种语言的映射到单独的文件
    os.makedirs(module_mapping_folder, exist_ok=True)
    for language, mapping in language_to_module_mapping.items():
        mapping_file = f"{module_mapping_folder}/{language}_module_to_filepath.json"
        with open(mapping_file, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False, indent=2)
        print(f"语言 {language} 的模块到路径映射已保存到 {mapping_file}")