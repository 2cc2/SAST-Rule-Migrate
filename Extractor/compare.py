import os

def get_all_files(directory):
    """
    递归获取目录下的所有文件路径。
    
    :param directory: 要搜索的目录路径
    :return: 文件名集合（不包含路径）
    """
    file_names = set()
    for root, _, files in os.walk(directory):
        for file in files:
            file_names.add(file)  # 只存储文件名
    return file_names

def compare_file_names(dir1, dir2):
    """
    比较两个目录中相同文件名的个数。
    
    :param dir1: 第一个目录路径
    :param dir2: 第二个目录路径
    :return: 相同文件名的个数和文件名列表
    """
    files1 = get_all_files(dir1)
    files2 = get_all_files(dir2)
    
    # 处理 files1 的文件名，截断 `_` 前面的部分
    truncated_files1 = set()
    for f in files1:
        file_name, _ = os.path.splitext(f)  # 分离文件名和扩展名
        truncated_file_name = file_name.split('_')[0]  # 截断文件名，取 `_` 前面的部分
        truncated_files1.add(truncated_file_name)
        for
    return len(common_files), common_files

if __name__ == "__main__":
    # 指定两个目录路径
    dir1 = "/home/cbb/Extractor/semgrep2codeql_XCPGIR_5cwe"
    dir2 = "/home/cbb/Extractor/java_classified_rules"
    
    # 比较文件名
    count, common_files = compare_file_names(dir1, dir2)
    
    # 输出结果
    print(f"两个目录中相同文件名的个数: {count}")
    if count > 0:
        print("相同的文件名如下：")
        for file in common_files:
            print(file)