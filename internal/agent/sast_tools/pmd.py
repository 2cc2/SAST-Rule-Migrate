import os
import re
import subprocess
import tempfile
import shutil


def extract_class_and_package(java_code: str):
    package_match = re.search(r'package\s+([\w.]+);', java_code)
    class_match = re.search(r'public\s+class\s+(\w+)', java_code)

    if not class_match:
        raise ValueError("未找到类定义")
    class_name = class_match.group(1)
    package_name = package_match.group(1) if package_match else ""

    rule_name = class_name
    rule_class = f"{package_name}.{class_name}" if package_name else class_name

    return rule_name, rule_class, class_name, package_name


def write_rule_to_java_file(java_file_path: str, rule_content: str):
    os.makedirs(os.path.dirname(java_file_path), exist_ok=True)
    with open(java_file_path, "w") as f:
        f.write(rule_content)



def generate_pom_xml(project_root: str):
    pom_path = os.path.join(project_root, "pom.xml")
    content = f"""<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-pmd-rules</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>jar</packaging>
    <name>My PMD Rules</name>

    <dependencies>
        <dependency>
            <groupId>net.sourceforge.pmd</groupId>
            <artifactId>pmd-core</artifactId>
            <version>6.47.0</version>
        </dependency>
        <dependency>
            <groupId>net.sourceforge.pmd</groupId>
            <artifactId>pmd-java</artifactId>
            <version>6.47.0</version>
        </dependency>
    </dependencies>
</project>
"""
    with open(pom_path, "w") as f:
        f.write(content)


def build_pmd_rule_project(project_dir: str) -> dict:
    result = {"valid": True, "error": ""}
    try:
        # 执行 Maven 构建命令
        process = subprocess.run(
            ["mvn", "clean", "install", "-DskipTests"],
            cwd=project_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
       

        if process.returncode != 0:
            result["valid"] = False
            result["error"] = process.stdout
            print(f"[❌] Maven 构建失败: {process.stderr.strip()}")
            return result

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    return result

def write_rule_to_xml_file(xml_file_path: str, rule_name: str, rule_class: str):
    """
    写入或更新 PMD 规则集 XML 文件，向其中加入一个 <rule> 元素
    """
    rule_entry = f"""
    <rule name="{rule_name}"
          language="java"
          class="{rule_class}"
          message="Custom PMD rule message." />
"""
    dir_path = os.path.dirname(xml_file_path)
    os.makedirs(dir_path, exist_ok=True)

    # 如果文件存在，追加规则；否则创建新规则集
    if os.path.exists(xml_file_path)and os.path.getsize(xml_file_path) > 0:
        with open(xml_file_path, "r") as file:
            content = file.read()

        # 在 </ruleset> 前插入新规则（避免重复插入）
        if rule_class not in content:
            content = content.replace("</ruleset>", f"{rule_entry}\n</ruleset>")
            with open(xml_file_path, "w") as file:
                file.write(content)
            print(f"[✅] XML 配置已更新，添加规则：{rule_name}")
        else:
            print(f"[ℹ️] 规则已存在于 XML 中：{rule_name}")
    else:
        # 创建新的 XML 文件
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<ruleset name="My Custom Rules"
         xmlns="http://pmd.sourceforge.net/ruleset/2.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://pmd.sourceforge.net/ruleset/2.0.0
                             http://pmd.sourceforge.net/ruleset_2_0_0.xsd">

    <description>Example custom PMD rule set.</description>
    {rule_entry}
</ruleset>
"""
        with open(xml_file_path, "w") as file:
            file.write(xml_content)
        print(f"[✅] XML 配置已创建：{xml_file_path}")




def validate_pmd_rule(rule: str, test_code: str = None):
    """
    构建并验证一个 PMD 自定义规则，rule 为 Java 规则代码，test_code 为用于测试的 Java 源码
    """
    temp_dir = "/Users/djoker/Desktop/CTGA/my-pmd-rules"
    try:
        rule_name, rule_class, class_name, package_name = extract_class_and_package(rule)

        java_file_path = os.path.join(temp_dir, "src/main/java/com/example/pmdrules", f"{class_name}.java")
        xml_file_path = os.path.join(temp_dir, "src/main/resources/rulesets/my-ruleset.xml")

        # 创建 POM 文件 + 写入规则源文件 & XML
        generate_pom_xml(temp_dir)
        write_rule_to_java_file(java_file_path, rule)
        write_rule_to_xml_file(xml_file_path, rule_name, rule_class)

        build_result = build_pmd_rule_project(temp_dir)
        return build_result
    except Exception as e:
        return {"valid": False, "error": str(e)}

# 示例调用
if __name__ == "__main__":
    rule_code = """package com.example.pmdrules;
public class Bod {
    public static void main(String[] args) {
        System.out.println("Hello, PMD!");
    }
}
"""
    test_src = "package test;\npublic class Hello { public static void main(String[] args) {} }"
    result = validate_pmd_rule(rule_code, test_src)
    if result["valid"]:
        print(f"[✅] PMD 规则验证通过")
    else:
        print(f"[❌] PMD 规则验证失败: {result['error']}")