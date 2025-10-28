#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import uuid
import shutil
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ------------ 配置区 ------------
codeql_path = "/home/cbb/codeql-cli/codeql/codeql"  # CodeQL 可执行文件路径
base_path = "/home/cbb/SAST-Rule-Migrate/migrate/test/codeql_test"  # 持久化目录
max_workers = 3  # 并发线程数
cmd_timeout = 300  # 子进程超时（秒）
keep_on_fail = True  # 是否在验证失败时保留临时目录
# ---------------------------------

packages_dir = os.path.expanduser("~/.codeql/packages")


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def write_codeql_pack_yaml(root_dir: str, language: str = "python"):
    """写入 codeql-pack.yml"""
    pack_file = os.path.join(root_dir, "codeql-pack.yml")
    with open(pack_file, "w") as f:
        f.write(
            f"name: sast/{language}-security-queries\n"
            "version: 0.0.1\n"
            "library: false\n"
            f"dependencies:\n  codeql/{language}-all: \"*\"\n"
        )
    return pack_file


def write_rule_file(rule_file: str, rule_content: str):
    with open(rule_file, "w", encoding="utf-8") as f:
        f.write(rule_content)


def write_sample_code(sample_file: str, language: str = "python"):
    """写入简单样例源码"""
    if language == "python":
        content = "import os\nos.system('ls')\n"
    elif language == "java":
        content = (
            "public class Sample {\n"
            "  public static void main(String[] args) {\n"
            "    Runtime.getRuntime().exec(\"ls\");\n"
            "  }\n"
            "}\n"
        )
    elif language == "javascript":
        content = "eval('console.log(1)');"
    else:
        content = "// sample\n"
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write(content)


def run_cmd(cmd, cwd=None, timeout=cmd_timeout):
  
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env={**os.environ, "CODEQL_PACKAGES_DIR": packages_dir}
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"TimeoutExpired: {e}"
    except Exception as e:
        return 1, "", f"Exception: {e}"


def validate_codeql_rule(rule_content: str, base_dir: str = base_path, language: str = "python"):
    """验证单个 CodeQL 规则"""
    result = {"valid": True, "error": ""}
    thread_id = uuid.uuid4().hex[:8]
    persist_path = os.path.join(base_dir, f"run_{thread_id}")

    try:
        ensure_dir(persist_path)

        root_dir = os.path.join(persist_path, f"{language}-security-queries")
        query_dir = os.path.join(root_dir, "queries", "test-rule")
        ensure_dir(query_dir)

        # 写入包配置与规则
        write_codeql_pack_yaml(root_dir, language)
        rule_file = os.path.join(query_dir, "TestRule.ql")
        write_rule_file(rule_file, rule_content)

        # 写入样例代码
        sample_dir = os.path.join(persist_path, "sample", language)
        ensure_dir(sample_dir)
        sample_file = os.path.join(sample_dir, f"vuln_example.{('py' if language == 'python' else 'java' if language == 'java' else 'js')}")
        write_sample_code(sample_file, language)

        # 创建 CodeQL 数据库
        db_path = os.path.join(persist_path, f"{language}-db")
        ensure_dir(db_path)

        print(f"[🔧] ({thread_id}) 正在创建 CodeQL 数据库...")

        # 根据语言切换数据库构建命令
        if language == "java":
            command = "mvn clean package -DskipTests"
            create_cmd = [
                codeql_path, "database", "create", db_path,
                "--language=" + language,
                "--source-root=" + sample_dir,
                "--command=" + command,
                "--overwrite"
            ]
            print(f"[🔄] ({thread_id}) 正在执行 Maven 构建命令：{command}")
        else:
            create_cmd = [
                codeql_path, "database", "create", db_path,
                "--language=" + language,
                "--source-root=" + sample_dir,
                "--overwrite"
            ]

        code, out, err = run_cmd(create_cmd)

        if code != 0:
            result["valid"] = False
            result["error"] = f"Database creation failed: {err.strip()}"
            return result

        # 安装依赖
        # print(f"[📦] ({thread_id}) 安装 CodeQL 依赖包...")
        # code, out_pack, err_pack = run_cmd([codeql_path, "pack", "install"], cwd=root_dir)
        # if code != 0:
        #     result["valid"] = False
        #     result["error"] = f"Pack install failed: {err_pack.strip()}"
        #     return result

        # 运行查询
        print(f"[🚀] ({thread_id}) 正在运行规则验证...")
        code, out, err = run_cmd([codeql_path, "query", "run", rule_file, "--database", db_path])
        if code != 0:
            result["valid"] = False
            result["error"] = err.strip() or "Unknown CodeQL failure"
        else:
            result["valid"] = True
            result["error"] = ""

        return result

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)
        return result

    finally:
        # 清理临时目录
        if os.path.exists(persist_path):
            try:
                shutil.rmtree(persist_path)
            except Exception as e:
                print(f"[cleanup warning] failed to remove {persist_path}: {e}")


def validate_rules_concurrently(rules, base_dir, max_workers=3, language="python"):
    """并发验证多个规则"""
    ensure_dir(base_dir)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(validate_codeql_rule, r, base_dir, language) for r in rules]
        for future in as_completed(futures):
            results.append(future.result())
    return results


if __name__ == "__main__":
    sample_rule = '''/**
 * @name Use of exec function
 * @description Detects usage of the exec function in Python code
 * @id python/exec-usage
 * @kind problem
 * @problem.severity warning
 * @tags security
 *       external/cwe/cwe-078
 */

import python

from Call call, Name name
where
  name = call.getFunc() and
  name.getId() = "exec"
select call, "Use of exec function detected"
'''
    rules = [sample_rule] * 3

    ensure_dir(base_path)
    print(f"[{datetime.now()}] Starting validation with {max_workers} workers...")
    result = validate_codeql_rule(sample_rule, base_path, language = "python")
    print(result)
    # results = validate_rules_concurrently(rules, base_path, max_workers=max_workers, language="python")

    # summary_path = os.path.join(base_path, "validation_summary.json")
    # with open(summary_path, "w", encoding="utf-8") as f:
    #     json.dump(results, f, indent=2, ensure_ascii=False)

    # print(f"[{datetime.now()}] Done. Results saved to {summary_path}")
    # for i, r in enumerate(results, 1):
    #     print(f"Rule {i}: valid={r['valid']}, error={r.get('error','')}")