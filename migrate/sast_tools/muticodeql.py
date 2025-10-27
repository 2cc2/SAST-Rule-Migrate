import os
import subprocess
import uuid
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# CodeQL 可执行文件路径
codeql_path = "/Users/djoker/Desktop/CodeQL/codeql/codeql"


# --- 工具函数 ---
def ensure_dir(path):
    """确保目录存在"""
    os.makedirs(path, exist_ok=True)


# --- 主验证函数 ---
def validate_codeql_rule(rule_content: str, base_path: str, language: str = "python") -> dict:
    """
    多线程安全的 CodeQL 规则验证函数
    每个线程使用独立的临时目录运行验证，结束后自动清理缓存。

    :param rule_content: CodeQL 查询规则内容
    :param base_path: 临时存放路径的根目录
    :param language: 编程语言（默认 python）
    :return: {'valid': bool, 'error': str}
    """
    result = {"valid": True, "error": ""}
    thread_id = uuid.uuid4().hex[:8]  # 每个线程独立 ID
    persist_path = os.path.join(base_path, f"run_{thread_id}")

    try:
        ensure_dir(persist_path)

        # 1. 构建 CodeQL 包结构
        root_dir = os.path.join(persist_path, f"{language}-security-queries")
        query_dir = os.path.join(root_dir, "queries/test-rule")
        ensure_dir(query_dir)

        # 写入 codeql-pack.yml
        with open(os.path.join(root_dir, "codeql-pack.yml"), "w") as f:
            f.write(
                f"name: sast/{language}-security-queries\n"
                f"version: 0.0.1\n"
                f"library: false\n"
                f"dependencies:\n  codeql/{language}-all: \"*\"\n"
            )

        # 写入 CodeQL 查询规则文件
        rule_file = os.path.join(query_dir, "TestRule.ql")
        with open(rule_file, "w") as f:
            f.write(rule_content)

        # 写入简单 Python 漏洞示例
        sample_dir = os.path.join(persist_path, "sample", language)
        ensure_dir(sample_dir)
        sample_file = os.path.join(sample_dir, "vuln_example.py")
        with open(sample_file, "w") as f:
            f.write("import os\nos.system('ls')\n")

        # 2. 创建 CodeQL 数据库
        db_path = os.path.join(persist_path, f"{language}-db")
        print(f"[🔧] ({thread_id}) 正在创建 CodeQL 数据库...")
        subprocess.run(
            [
                codeql_path, "database", "create", db_path,
                "--language=" + language,
                "--source-root=" + sample_dir,
                "--overwrite"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 3. 运行 CodeQL 查询验证
        print(f"[🚀] ({thread_id}) 正在运行规则验证...")
        process = subprocess.run(
            [codeql_path, "query", "run", rule_file, "--database", db_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if process.returncode != 0:
            result["valid"] = False
            result["error"] = process.stderr.strip() or "Unknown CodeQL failure"
        else:
            print(f"[✅] ({thread_id}) 验证通过")

    except subprocess.CalledProcessError as e:
        result["valid"] = False
        result["error"] = e.stderr.strip() or str(e)

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    finally:
        # ✅ 验证完成后自动清理缓存目录
        try:
            shutil.rmtree(persist_path)
            print(f"[🧹] ({thread_id}) 已删除临时目录 {persist_path}")
        except Exception as cleanup_err:
            print(f"[⚠️] ({thread_id}) 删除临时目录失败: {cleanup_err}")

    return result


# --- 多线程批量执行 ---
def validate_rules_concurrently(rules, base_path, max_workers=3, language="python"):
    """
    并发验证多条 CodeQL 规则。
    """
    ensure_dir(base_path)
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(validate_codeql_rule, rule, base_path, language)
            for rule in rules
        ]
        for future in as_completed(futures):
            results.append(future.result())

    return results


# --- 主程序入口 ---
if __name__ == "__main__":
    base_path = "/Users/djoker/Desktop/CTGA/test/codeql_test"
    ensure_dir(base_path)

    # 示例规则（Python）
    rule = '''import python

from Call c
where c.getTarget().getName() = "system"
select c, "Potential command injection via os.system"
'''

    # 模拟 3 条规则并发验证
    rules = [rule] * 3
    results = validate_rules_concurrently(rules, base_path, max_workers=3, language="python")

    print("\n=== 验证结果汇总 ===")
    for i, res in enumerate(results, 1):
        print(f"规则 {i}: {res}")