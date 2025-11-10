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
# codeql_path = "/home/cbb/codeql2/codeql/codeql"
base_path = "/home/cbb/SAST-Rule-Migrate/internal/share/test/codeql_test"  # 持久化目录
max_workers = 1  # 并发线程数
cmd_timeout = 300  # 子进程超时（秒）
keep_on_fail = True  # 是否在验证失败时保留临时目录
# ---------------------------------

packages_dir = os.path.expanduser("/home/cbb/.codeql/packages/")
# codeql_version = "2.18.5"

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)




def write_codeql_pack_yaml(root_dir: str, language: str = "java"):
    """写入 codeql-pack.yml"""
    pack_file = os.path.join(root_dir, "codeql-pack.yml")

    # ✅ 对 Java 语言显式依赖 java-all 和 java-queries
    if language == "java":
        dependencies = (
            "dependencies:\n"
            "  codeql/java-all: \"*\"\n"
            "  codeql/java-queries: \"*\"\n"
        )
    else:
        dependencies = f"dependencies:\n  codeql/{language}-all: \"*\"\n"

    with open(pack_file, "w") as f:
        f.write(
            f"name: sast/{language}-security-queries\n"
            "version: 0.0.1\n"
            "library: false\n"
            f"{dependencies}"
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
            "package com.example;\n\n"
            "public class Sample {\n"
            "  public static void main(String[] args) {\n"
            "    try {\n"
            "      Runtime.getRuntime().exec(\"ls\");\n"
            "    } catch (Exception e) {\n"
            "      e.printStackTrace();\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        # 写入 pom.xml 文件
        pom_content = """<project xmlns="http://maven.apache.org/POM/4.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>sample</artifactId>
    <version>1.0-SNAPSHOT</version>
    <properties>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>
</project>
"""
        sample_dir = os.path.dirname(sample_file)
        pom_file = os.path.join(sample_dir, "pom.xml")
        with open(pom_file, "w", encoding="utf-8") as f:
            f.write(pom_content)
        # 创建 src/main/java/com/example 目录结构
        java_src_dir = os.path.join(sample_dir, "src", "main", "java", "com", "example")
        ensure_dir(java_src_dir)
        sample_file = os.path.join(java_src_dir, "Sample.java")
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


def validate_codeql_rule(rule_content: str, base_dir: str = base_path, language: str = "java"):
    """验证单个 CodeQL 规则"""
    result = {"valid": True, "error": ""}
    thread_id = uuid.uuid4().hex[:8]
    persist_path = os.path.join(base_dir, f"run_{thread_id}")

    try:
        ensure_dir(persist_path)
        if persist_path:
            print("存在",persist_path)
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
                "--search-path=" + packages_dir,
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
        lock_src = "/home/cbb/SAST-Rule-Migrate/internal/share/codeql-pack.lock.yml"
        lock_dst = os.path.join(root_dir, "codeql-pack.lock.yml")
        if os.path.exists(lock_src):
            shutil.copy(lock_src, lock_dst)
            print(f"[🧩] ({thread_id}) 已复制本地 lock 文件，跳过 pack install")
        else:
            print(f"[📦] ({thread_id}) 未找到缓存 lock 文件，正在执行 pack install ...")
            code, out_pack, err_pack = run_cmd([codeql_path, "pack", "install"], cwd=root_dir)
        # 运行查询
        print(f"[🚀] ({thread_id}) 正在运行规则验证...")
        code, out, err = run_cmd([codeql_path, "query", "run", rule_file, "--database",db_path,"--search-path=" + packages_dir,])
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
                # shutil.rmtree(persist_path)
                print(persist_path)
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


def validate_rules_in_directory(rules_dir, base_dir, max_workers=3, language="java"):
    """
    验证指定目录下的所有规则文件。
    """
    ensure_dir(base_dir)
    results = []
    rule_files = []

    # 遍历目录，找到所有 .ql 文件
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".go"):
                rule_files.append(os.path.join(root, file))

    print(f"[🔍] 找到 {len(rule_files)} 个规则文件，开始验证...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(validate_codeql_rule, open(rule_file, "r", encoding="utf-8").read(), base_dir, language): rule_file
            for rule_file in rule_files
        }
        for future in as_completed(futures):
            rule_file = futures[future]
            try:
                result = future.result()
                results.append({"file": rule_file, "result": result})
                if result["valid"]:
                    print(f"[✅] 验证通过: {rule_file}")
                else:
                    print(f"[❌] 验证失败: {rule_file} - {result['error']}")
            except Exception as e:
                print(f"[⚠️] 验证异常: {rule_file} - {e}")

    # 保存验证结果到文件
    results_file = os.path.join(base_dir, "validation_results.json")
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"[📄] 验证结果已保存到 {results_file}")

if __name__ == "__main__":
    rules_directory = "/home/cbb/PJ/SAST-Rule-Migrate/output/semgrep2codeql"
    validate_rules_in_directory(rules_directory, base_path, max_workers=max_workers, language="java")


def ensure_codeql_deps_installed():
    """检查并安装 CodeQL 依赖包"""
    print("[🧩] 检查 CodeQL Java 依赖包...")
    try:
        installed = subprocess.run(
            ["codeql", "resolve", "packs"],
            capture_output=True, text=True, check=True
        ).stdout

        required = ["codeql/java-all", "codeql/java-queries"]
        for pkg in required:
            if pkg not in installed:
                print(f"[⬇️] 未找到 {pkg}，开始安装...")
                subprocess.run(["codeql", "pack", "install", pkg], check=True)
            else:
                print(f"[✅] 已安装 {pkg}")
    except Exception as e:
        print(f"[❌] 检查 CodeQL 包失败: {e}")


