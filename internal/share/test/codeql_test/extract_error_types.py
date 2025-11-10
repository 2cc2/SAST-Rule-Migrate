import json

def extract_unique_error_types(file_path):
    """提取 JSON 文件中所有唯一的错误类型"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 假设错误类型存储在每条记录的 "error_type" 字段中
        error_types = set()
        for record in data:
            error_type = record.get("error_type")  # 替换为实际的错误类型字段名
            if error_type:
                error_types.add(error_type)

        print(f"发现的唯一错误类型 ({len(error_types)}):")
        for error in error_types:
            print(f"- {error}")

        return error_types

    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
    except json.JSONDecodeError:
        print(f"无法解析 JSON 文件: {file_path}")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    # 替换为实际的 JSON 文件路径
    json_file_path = "/home/cbb/SAST-Rule-Migrate/internal/share/test/codeql_test/validation_results.json"
    extract_unique_error_types(json_file_path)