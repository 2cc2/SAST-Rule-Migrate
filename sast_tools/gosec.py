import subprocess
import os
import re

# Define constants for file paths and directories
PROJECT_DIR = "/Users/djoker/Desktop/CTGA/gosec"
RULELIST_FILE = os.path.join(PROJECT_DIR, "rules/rulelist.go")
RULE_FILE_TEMPLATE = os.path.join(PROJECT_DIR, "rules/{rule_id}.go")
REPORT_DIR = "/Users/djoker/Desktop/CTGA/reports"
GOCUSTOMRULE_FILE = "/Users/djoker/Desktop/CTGA/gocustomrule/rule.go"
GOSEC_EXECUTABLE = os.path.join(PROJECT_DIR, "gosec")
TEST_CODE = "package main\nfunc main() {\nprintln(\"hello\")\n}"

def write_rule_to_rulelist(register_file: str, register_id: str, register_description: str, register_name: str):
    """
    将规则写入到 rulelist.go 文件中。
    :param register_file: rulelist.go 文件路径
    :param register_id: 规则 ID
    :param register_description: 规则描述
    :param register_name: 规则名称
    """
    if not os.path.exists(register_file):
        print(f"[❌] 文件 {register_file} 不存在")
        return
    # 读取 rulelist.go 文件内容
    with open(register_file, "r") as f:
        content = f.readlines()
    # 找到 rules 列表的位置
    for i, line in enumerate(content):
        if "rules := []RuleDefinition{" in line:
            insert_index = i + 1
            break
    else:
        print("[❌] 未找到 rules 列表定义")
        return
    # 生成规则代码
    new_rule = f'        {{"{register_id}", "{register_description}", {register_name}}},\n'
    # 检查是否有重复内容
    # 检查是否有重复内容
    for i, line in enumerate(content):
    # 提取规则的 ID、描述和名称
        match = re.search(r'{\s*"([^"]+)",\s*"([^"]+)",\s*(\w+)\s*}', line.strip())
        if match:
            existing_id, existing_description, existing_name = match.groups()
        # 检查是否有重复的 ID、描述或名称
            if register_id == existing_id or register_description == existing_description or register_name == existing_name:
                print(f"【👏] 规则已存在，删除重复内容: {line.strip()}")
                content.pop(i)
                break
    # 插入规则
    content.insert(insert_index, new_rule)
    # 写回文件
    with open(register_file, "w") as f:
        f.writelines(content)
    print(f"[✅] 规则 {register_id} 已成功写入到 {register_file}")

def write_rule_to_rule(rule: str, rule_file: str):
    """
    将规则内容写入到指定的规则文件中。
    :param rule: 规则内容
    :param rule_file: 规则文件路径
    """
    with open(rule_file, "w") as f:
        f.write(rule)
    print(f"[✅] 规则已成功写入到 {rule_file}")

def load_rule_from_file(file_path: str) -> str:
    """
    从指定文件中加载 YAML 规则内容。
    :param file_path: 文件路径
    :return: YAML 规则内容字符串
    """
    if not os.path.exists(file_path):
        print(f"[❌] 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()
    print(f"[✔] 成功从文件 {file_path} 加载规则内容")
    return yaml_content.strip()

def validate_gosec_rule(rule: str) -> dict:
    """
    验证 Gosec 是否能正常扫描代码。
    在分析之前，写入规则到 rulelist.go 和规则文件，并执行 make clean 和 make 操作。
    :param rule: 规则内容
    :param register_file: rulelist.go 文件路径
    :param register_id: 规则 ID
    :param register_description: 规则描述
    :param register_name: 规则名称
    :param rule_file: 规则文件路径
    :param test_code: 用于测试的简单代码（Go语言）
    :return: 结果字典 {'valid': bool, 'error': str}
    """
     # 匹配以 func New 开头的函数名
    pattern = r'func\s+(New\w+)'
    match = re.search(pattern, rule)
    if match:
        register_name = match.group(1)  # Captures "NewBadTmpFile"
        print(f"Function Name: {register_name}")
    else:
        print("No matching function signature found.")

    register_id = "GC001"
    register_description = "This is a test rule for Gosec validation."
    register_file = RULELIST_FILE
    rule_file = RULE_FILE_TEMPLATE.format(rule_id=register_id)

    result = {"valid": True, "error": ""}
    try:
        # 写入规则到 rulelist.go 和规则文件
        write_rule_to_rulelist(register_file, register_id, register_description, register_name)
        write_rule_to_rule(rule, rule_file)
        # 执行 make clean 和 make 操作
        print("[🔄] 执行 make clean")
        subprocess.run(["make", "clean"], cwd=PROJECT_DIR, check=True, capture_output=True, text=True)
        print("[🔄] 执行 make")
        subprocess.run(["make"], cwd=PROJECT_DIR, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[❌] make 命令执行失败: {e}")
        result["valid"] = False
        result["error"] = f"make failed with error:\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}"
    return result

if __name__ == "__main__":
    rule = load_rule_from_file(GOCUSTOMRULE_FILE)
    print("[📜] 加载的 Gosec 规则内容：")
    
   

    # 验证规则
    validation_result = validate_gosec_rule(rule)
    if validation_result["valid"]:
        print("[✅] Gosec 验证成功")
    else:
        print(f"[❌] Gosec 验证失败: {validation_result['error']}")