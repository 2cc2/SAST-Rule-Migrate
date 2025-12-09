import os

def list_yaml_files(folder_path):
    """
    递归列出指定文件夹及其子文件夹下所有以 .yaml 结尾的文件。

    Args:
        folder_path (str): 文件夹路径。

    Returns:
        list: 所有以 .yaml 结尾的文件的完整路径列表。
    """
    sum=0
    yaml_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            # print(file)
            if file.endswith(".yaml"):  # 筛选出 .yaml 文件
                yaml_files.append(os.path.join(root, file))
                sum+=1

    print(f"总共找到 {sum} 个 .yaml 文件。")
    return yaml_files

# 指定文件夹路径
# folder_path = "/home/cbb/SAST-Rule-Migrate/input/semgrep/python_classified_rules/"
folder_path = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/IrBase/PyIR"
# 调用函数并打印结果
yaml_file_names = list_yaml_files(folder_path)
print(f"文件夹 '{folder_path}' 及其子文件夹下的所有 .yaml 文件如下：")
# for file_name in yaml_file_names:
#     print(file_name)