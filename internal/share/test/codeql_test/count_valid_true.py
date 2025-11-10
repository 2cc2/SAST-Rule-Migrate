import json

def count_valid_true(file_path):
    """统计 JSON 文件中 valid 为 true 的记录次数"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 统计 valid 为 true 的记录次数
        valid_count = 0
        for record in data:
            result = record.get("result")
            if result and result.get("valid") is True:  # 直接检查布尔值
                valid_count += 1

        print(f"valid 为 true 的记录次数: {valid_count}")
        return valid_count

    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
    except json.JSONDecodeError:
        print(f"无法解析 JSON 文件: {file_path}")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    # 替换为实际的 JSON 文件路径
    json_file_path = "/home/cbb/SAST-Rule-Migrate/internal/share/test/codeql_test/validation_results.json"
    count_valid_true(json_file_path)