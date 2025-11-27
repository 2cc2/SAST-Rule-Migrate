import json

def sort_imports_by_filepath_count(input_file, output_file):
    """
    根据路径数量对 imports 进行排序

    Args:
        input_file (str): 输入的 JSON 文件路径
        output_file (str): 输出的排序后 JSON 文件路径
    """
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 按路径数量排序
        sorted_data = {
            k: v for k, v in sorted(data.items(), key=lambda item: len(item[1]), reverse=True)
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sorted_data, f, ensure_ascii=False, indent=2)

        print(f"排序后的结果已保存到 {output_file}")

    except Exception as e:
        print(f"处理文件时出错: {e}")


if __name__ == "__main__":
    input_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/import_mappings/java_import_to_filepath.json"
    output_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/import_mappings/java_import_to_filepath_sorted.json"

    sort_imports_by_filepath_count(input_file, output_file)