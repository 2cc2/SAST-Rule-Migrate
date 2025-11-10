import subprocess
import tempfile
import os
import yaml

def validate_semgrep_rule(rule_yaml: str, test_code: str = "print('hello')") -> dict:
    """
    验证 Semgrep 规则是否能正常使用。

    :param rule_yaml: Semgrep 规则字符串（YAML格式）
    :param test_code: 用于测试的简单代码
    :return: 结果字典 {'valid': bool, 'error': str}
    """
    result = {"valid": True, "error": ""}
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # 写入规则文件
            rule_path = os.path.join(tmpdir, "rule.yml")
            with open(rule_path, "w") as f:
                f.write(rule_yaml)

            code_path = os.path.join(tmpdir, "test.go")
            with open(code_path, "w") as f:
                f.write(test_code)
            print(f"[✅] 临时目录已创建：{tmpdir}")
            # 调用 semgrep 进行规则测试
            process = subprocess.run(
                ["semgrep", "--config", rule_path, code_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if process.returncode != 0:
                result["valid"] = False
                result["error"] = process.stderr.strip() or "Unknown semgrep failure"

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)
            # 记录异常信息到日志文件
    return result