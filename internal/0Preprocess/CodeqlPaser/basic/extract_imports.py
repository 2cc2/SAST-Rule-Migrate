import json


def extract_imports_and_modules_from_json(input_file, imports_output_file, modules_output_file):
    """
    从 JSON 文件中提取所有 imports 和 modules 并分别保存到输出文件

    Args:
        input_file (str): 输入的 JSON 文件路径
        imports_output_file (str): imports 输出的文件路径
        modules_output_file (str): modules 输出的文件路径
    """
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        all_imports = set()
        all_modules = set()

        for file_path, content in data.items():
            imports = content.get("imports", [])
            modules = content.get("modules", [])
            all_imports.update(imports)
            all_modules.update(modules)

        with open(imports_output_file, "w", encoding="utf-8") as f:
            for imp in sorted(all_imports):
                f.write(imp + "\n")

        with open(modules_output_file, "w", encoding="utf-8") as f:
            for mod in sorted(all_modules):
                f.write(mod + "\n")

        print(f"所有 imports 已提取并保存到 {imports_output_file}")
        print(f"所有 modules 已提取并保存到 {modules_output_file}")

    except Exception as e:
        print(f"处理文件时出错: {e}")


def compare_imports_and_modules(input_file, comparison_output_file):
    """
    比较 JSON 文件中的 imports 和 modules，找出相同和不同的部分

    Args:
        input_file (str): 输入的 JSON 文件路径
        comparison_output_file (str): 比较结果输出的文件路径
    """
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        all_imports = set()
        all_modules = set()

        for file_path, content in data.items():
            imports = content.get("imports", [])
            modules = content.get("modules", [])

            # 对列表中的每个元素进行处理
            imports = [imp.split('.')[0] for imp in imports]
            modules = [mod.split('.')[0] for mod in modules]

            all_imports.update(imports)
            all_modules.update(modules)

        # 比较相同和不同的部分
        common = all_imports & all_modules
        only_in_imports = all_imports - all_modules
        only_in_modules = all_modules - all_imports

        comparison_result = {
            "common": list(sorted(common)),
            "only_in_imports": list(sorted(only_in_imports)),
            "only_in_modules": list(sorted(only_in_modules))
        }

        with open(comparison_output_file, "w", encoding="utf-8") as f:
            json.dump(comparison_result, f, ensure_ascii=False, indent=2)

        print(f"imports 和 modules 的比较结果已保存到 {comparison_output_file}")

    except Exception as e:
        print(f"处理文件时出错: {e}")


if __name__ == "__main__":
    input_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/imports_modules_outputs/java_results.json"
    imports_output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/imports_modules_outputs/java_imports.txt"
    modules_output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/imports_modules_outputs/java_modules.txt"
    comparison_output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/imports_modules_outputs/java_comparison.json"

    extract_imports_and_modules_from_json(input_file, imports_output_file, modules_output_file)
    compare_imports_and_modules(input_file, comparison_output_file)