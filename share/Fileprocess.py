import re
import os
from datetime import datetime

def get_rule_from_llm(response: str) -> str:
    """
    从 LLM 的响应中提取 QL 代码块。
    参数:
        response (str): LLM 返回的字符串响应，可能包含 Markdown 格式的 QL 代码块。
    返回:
        str: 提取的 QL 代码块内容。如果未找到符合格式的代码块，返回空字符串。
    """
    matches = re.findall(r"```ql\n(.*?)```", response, re.DOTALL)
    if matches:
        thread_print("✔ 成功提取 Markdown 中的 QL 代码块")
        return matches[0].strip()
    else:
        thread_print("❌ 未找到符合格式的 QL 代码块")
        return ""

def save_rule(yaml_text: str, output_dir: str, file_name: str):
    """
    将规则内容保存为 .ql 文件。
    参数:
        yaml_text (str): 要保存的规则内容。
        output_dir (str): 保存文件的目标目录。
        base_name (str): 文件的基础名称，默认为 "semgrep_rule"。
    返回:
        None
    """
    os.makedirs(output_dir, exist_ok=True)  # 确保目标目录存在
    file_path = os.path.join(output_dir, file_name)  # 构造文件路径
    with open(file_path, "w") as f:
        f.write(yaml_text)  # 写入规则内容
    thread_print(f"✔ 规则已保存到 {file_path}")

def save_IR(yaml_text: str, output_dir: str, base_name: str):
    """
    将中间表示 (IR) 内容保存为 .yaml 文件。
    参数:
        yaml_text (str): 要保存的 IR 内容。
        output_dir (str): 保存文件的目标目录。
        base_name (str): 文件的基础名称，默认为 "semgrep_rule"。

    返回:
        None
    """
    os.makedirs(output_dir, exist_ok=True)  # 确保目标目录存在
    file_path = os.path.join(output_dir, f"{base_name}.yaml")  # 构造文件路径
    with open(file_path, "w") as f:
        f.write(yaml_text)  # 写入 IR 内容
    thread_print(f"✔ IR 已保存到 {file_path}")

def load_rule_from_file(file_path: str) -> str:
    """
    从文件中加载规则内容。

    参数:
        file_path (str): 要加载的文件路径。

    返回:
        str: 文件中的规则内容。如果文件不存在，返回空字符串。
    """
    if not os.path.exists(file_path):  # 检查文件是否存在
        thread_print(f"❌ 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()  # 读取文件内容
    thread_print(f"✔ 成功从文件 {file_path} 加载内容")
    return yaml_content.strip()

def get_yaml_files(directory):
    """
    获取指定目录及其子目录中所有 .yaml 文件的路径。

    参数:
        directory (str): 要搜索的目录路径。

    返回:
        list: 包含所有 .yaml 文件路径的列表。
    """
    yaml_files = []
    for root, _, files in os.walk(directory):  # 遍历目录及子目录
        for file in files:
            if file.endswith(".yaml"):  # 检查文件扩展名
                yaml_files.append(os.path.join(root, file))  # 添加文件路径到列表
    return yaml_files