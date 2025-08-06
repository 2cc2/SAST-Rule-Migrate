import os

def list_files_in_directory(directory_path):
    """
    获取指定文件夹下的所有文件名。
    :param directory_path: 文件夹路径
    :return: 文件名列表
    """
    try:
        # 检查目录是否存在
        if not os.path.exists(directory_path):
            print(f"[❌] 文件夹 {directory_path} 不存在")
            return []

        # 获取文件夹中的所有文件名
        files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]
        return files
    except Exception as e:
        print(f"[⚠️] 发生错误：{e}")
        return []

def extract_prefix(filename, delimiter='_2025'):
    """
    从文件名中提取指定分隔符之前的内容。
    :param filename: 文件名字符串
    :param delimiter: 分隔符，默认值为 '_2025'
    :return: 提取后的字符串
    """
    return filename.split(delimiter)[0]

if __name__ == "__main__":
    # 替换为你的目标文件夹路径
    target_directory = "/Users/djoker/Desktop/CTGA/demo/input/gosec/rules"
    file_names = list_files_in_directory(target_directory)
    # 提取文件名的前缀部分
    gosec_rule_basenames = [extract_prefix(file, '.') for file in file_names]

    # 替换为你的目标文件夹路径
    target_directory = "/Users/djoker/Desktop/CTGA/demo/output/gosec"
    file_names = list_files_in_directory(target_directory)
    # 提取文件名的前缀部分
    rule_basenames = [extract_prefix(file) for file in file_names]

    target_directory = "/Users/djoker/Desktop/CTGA/demo/output/gosec_2"
    file_names = list_files_in_directory(target_directory)
    # 提取文件名的前缀部分
    rule_basenames2 = [extract_prefix(file) for file in file_names]

    # 合并 basenames
    combined_basenames = set(rule_basenames) | set(rule_basenames2)
    print("combined", len(combined_basenames))
    # 找到缺失的 basenames
    missing_basenames = set(gosec_rule_basenames) - combined_basenames
    print(len(combined_basenames))
    # 按字典顺序输出
    print(sorted(missing_basenames))  # 按字典顺序输出
    print(sorted(rule_basenames))  # 按字典顺序输出
    print(sorted(rule_basenames2))  # 按字典顺序输出
    print(sorted(gosec_rule_basenames))  # 按字典顺序输出