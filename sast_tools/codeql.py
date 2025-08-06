import os
import subprocess

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)
codeql_path = "/Users/djoker/Desktop/CodeQL/codeql-cli/codeql"
def validate_codeql_rule(rule_content: str,persist_path: str = "./persistent_codeql",language: str = "java") -> dict:
    """
    验证 CodeQL 查询规则是否能正常使用，并将所有内容持久化。

    :param rule_content: CodeQL 查询规则内容
    :param test_code: 用于测试的代码（可选，根据语言动态生成默认代码）
    :param persist_path: 持久化存储的路径
    :param language: 测试代码的语言（如 'java', 'python', 'javascript' 等）
    :return: 结果字典 {'valid': bool, 'error': str}
    """
    result = {"valid": True, "error": ""}
    try:
        # 确保持久化路径存在
        ensure_dir(persist_path)

        # 创建目录结构
        root_dir = os.path.join(persist_path, f"{language}-security-queries")
        query_dir = os.path.join(root_dir, "queries")
        ensure_dir(query_dir)

        # 写入 codeql-pack.yml
        pack_file = os.path.join(root_dir, "codeql-pack.yml")
        with open(pack_file, "w") as f:
            f.write(
                f"name: sast/{language}-security-queries\n"
                "version: 0.0.1\n"
                "library: false\n"
                f"dependencies:\n  codeql/{language}-all: \"*\"\n"
            )

        # 写入规则文件
        rule_dir = os.path.join(query_dir, "test-rule")
        ensure_dir(rule_dir)
        rule_file = os.path.join(rule_dir, "TestRule.ql")
        with open(rule_file, "w") as f:
            f.write(rule_content)

        # 写入测试代码
        sample_dir = os.path.join(persist_path, "sample")
        print(f"[✔] 测试代码将写入目录：{sample_dir}")
        src_dir = os.path.join(sample_dir, language)
        print(f"[✔] 源代码将写入目录：{src_dir}")
        db_path = os.path.join(persist_path, f"{language}-db")
        print(f"[✔] 数据库将写入目录：{db_path}")
        ensure_dir(src_dir)
        ensure_dir(db_path)

        # 1. 创建 CodeQL 数据库
        if language == "java":
            command = "mvn clean package -DskipTests"
            create_cmd = [
                codeql_path, "database", "create", str(db_path),
                "--language=" + language,
                "--source-root=" + str(src_dir),
                "--command=" + command,
                "--overwrite"
            ]
            print(f"[🔄] 正在执行 Maven 命令：{command}")
        else:
            # 默认构建
            create_cmd = [
                codeql_path, "database", "create", str(db_path),
                "--language=" +  language,
                "--source-root=" + str(src_dir),
                "--overwrite"
            ]
        # subprocess.run(create_cmd, check=True)
        # 初始化 CodeQL 数据库
        print("[✔] CodeQL 数据库已创建")
        # 运行 CodeQL 查询
        process = subprocess.run(
            ["codeql", "query", "run", rule_file, "--database","/Users/djoker/Desktop/CTGA/test/codeql_test/java-db"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if process.returncode != 0:
            result["valid"] = False
            result["error"] = process.stderr.strip() or "Unknown CodeQL failure"
    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)
    return result

# 示例用法
if __name__ == "__main__":
    rule = '''import java

    from MethodCall mc
    where mc.getMethod().hasName("exec")
    select mc, "This method call executes a system command."
    '''
    persist_path = "/Users/djoker/Desktop/CTGA/test/codeql_test"
    validation_result = validate_codeql_rule(rule, persist_path=persist_path, language="java")
    print(validation_result)