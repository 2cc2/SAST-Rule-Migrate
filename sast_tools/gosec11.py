import subprocess
import os

def validate_gosec_rule(rule:str,test_code: str = "package main\nfunc main() {\nprintln(\"hello\")\n}") -> dict:
    """
    验证 Gosec 是否能正常扫描代码。

    :param test_code: 用于测试的简单代码（Go语言）
    :return: 结果字典 {'valid': bool, 'error': str}
    """
    result = {"valid": True, "error": ""}
    try:
        # 使用持久目录保存报告
        report_dir = "/Users/djoker/Desktop/CTGA/reports"
        os.makedirs(report_dir, exist_ok=True)  # 确保目录存在
        report_path = os.path.join(report_dir, "gosec_report.json")

        code_path = "/Users/djoker/Desktop/CTGA/test/"
        # 构建 gosec 命令
        cmd = [
            "/Users/djoker/Desktop/CTGA/gosec/gosec",  # 替换为你的 gosec 可执行文件路径
            "-fmt", "json",  # 输出格式为 JSON
            "-out", report_path,  # 输出报告路径
            "--no-fail", 
            code_path
        ]
        print(f"[🔄] 正在执行 Gosec 命令：{' '.join(cmd)}")
        # 调用 gosec 扫描测试代码
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if process.returncode != 0:
            print(f"[❌] Gosec 扫描失败，返回代码：{process.returncode}")
            result["valid"] = False
            result["error"] = process.stderr.strip() or "Unknown gosec failure"
        else:
            print(f"[📄] 扫描报告已生成：{report_path}")

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    return result
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
if __name__ == "__main__":
    test_code = "package main\nfunc main() {\nprintln(\"hello\")\n}"
    rule= load_rule_from_file("/Users/djoker/Desktop/CTGA/gocustomrule/rule.go")
    print("[📜] 加载的 Gosec 规则内容：")
    register_name=""
    register_id="GC001"
    register_des
    print(rule)
    register_file = "/Users/djoker/Desktop/CTGA/gosec/rules/rulelist.go"
    rule_file="/Users/djoker/Desktop/CTGA/gosec/rules/A77.go"
    validation_result = validate_gosec_rule(rule,test_code)
    if validation_result["valid"]:
        print("[✅] Gosec 验证成功")
    else:
        print(f"[❌] Gosec 验证失败: {validation_result['error']}")