#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
为CodeQL示例文件添加标签的脚本

该脚本读取codeql_example.json文件，为每个规则的examples列表中的每个example添加一个label字段，
值为"good"、"bad"、"unknown"或"both"之一。

输入文件: codeql_example.json
输出文件: codeql_example_labeled.json
"""

import json
import os
from typing import Dict, Any, List
from openai import OpenAI  # 假设使用OpenAI或兼容的API

# 配置文件路径
CODEQL_EXAMPLE_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_examples.json"
CODEQL_EXAMPLE_LABELED_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example_labeled.json"
CODEQL_ROOT = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql"

# 初始化OpenAI客户端
client = OpenAI(
    api_key=os.environ.get("LLM_API_KEY"),
    base_url="https://4.0.wokaai.com/v1/chat/completions"
)


def load_json_file(filepath: str) -> Dict[str, Any]:
    """加载JSON文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(filepath: str, data: Dict[str, Any]) -> None:
    """保存JSON文件"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def read_file_content(filepath: str, with_lineno: bool = False) -> str:
    """读取文件内容，如果文件不存在或无法读取则返回空字符串"""
    if filepath.startswith('\\'):
        filepath = filepath[1:]
    full_path = os.path.join(CODEQL_ROOT, filepath)
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if with_lineno:
                lines = [f"{i+1}    {line}" for i, line in enumerate(lines)]
            return ''.join(lines)
    except Exception as e:
        print(f"警告: 无法读取文件 {full_path}: {e}")
        return ""


def determine_label_with_llm(rule_path: str, example_path: str, goodcase: int, badcase: int):
    """
    使用大模型根据规则文件、示例文件内容确定标签
    
    标签原则:
    - 若由文件名或内容能判断出，该例子应能检测出漏洞，则label为"bad"
    - 若由文件名或内容能判断出，该例子不能检测出漏洞，则label为"good"
    - 若由文件名或内容不能判断出，则label为"unknown"
    - 若由文件名或内容能判断出，该例子分为多个部分，有的部分应检出漏洞，有的部分不应检出，则label为"both"
    """
    # 读取规则文件内容
    rule_content = read_file_content(rule_path)
    
    # 读取示例文件内容
    example_content = read_file_content(example_path,  True)
    
    # 构造提示词
    system_prompt = f"""我需要评测Codeql规则在具体程序示例上的检测性能。一个程序示例中，有多个good,safe/bad,unsafe的代码片段作为检查点。我需要根据规则是否命中这些代码片段区间，作为Codeql规则性能的评价指标。
请根据Codeql规则文件和示例文件的路径和内容，返回该示例文件中，各个代码片段检查点的区间，并返回该区间的标签。

具体要求如下：
1. 如果示例文件中，存在漏洞的代码，即使用规则检测该代码位置，Codeql应该在某个区间告警，则输出(bad, 区间起点行号， 区间终点行号)。
2. 如果示例文件中，有安全的、用以检测规则误报情况的代码，即使用规则检测该代码位置，Codeql不应该在某个区间告警，则输出(good, 区间起点行号，区间终点行号)
3. 如果示例文件中，不存在以上两种情况，或示例文件不应该对应该规则，则不返回任何内容。

============输出规范==============
请输出所有的匹配情况（其中，行号区间应将示例程序中的每个检查点区分开；同时这些区间的并集应尽可能覆盖整个程序，以提高规则性能评估的容错率），每行一个，例如：
(bad, 13, 18)
(bad, 19, 29)
(good, 30, 35)
(good, 36, 44)
(good, 45, 55)

++++++++++示例开始++++++++++++
====规则文件路径===== 
java/ql/src/Security/CWE/CWE-129/ImproperValidationOfArrayConstruction.ql
====规则文件内容=====
/**
 * @name Improper validation of user-provided size used for array construction
 * @description Using unvalidated external input as the argument to a construction of an array can lead to index out of bound exceptions.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id java/improper-validation-of-array-construction
 * @tags security
 *       external/cwe/cwe-129
 */

import java
import semmle.code.java.security.internal.ArraySizing
import semmle.code.java.security.ImproperValidationOfArrayConstructionQuery
import ImproperValidationOfArrayConstructionFlow::PathGraph

from
  ImproperValidationOfArrayConstructionFlow::PathNode source,
  ImproperValidationOfArrayConstructionFlow::PathNode sink, Expr sizeExpr,
  ArrayCreationExpr arrayCreation, CheckableArrayAccess arrayAccess
where
  arrayAccess.canThrowOutOfBoundsDueToEmptyArray(sizeExpr, arrayCreation) and
  sizeExpr = sink.getNode().asExpr() and
  ImproperValidationOfArrayConstructionFlow::flowPath(source, sink)
select arrayAccess.getIndexExpr(), source, sink,
  "This accesses the $@, but the array is initialized using a $@ which may be zero.", arrayCreation,
  "array", source.getNode(), "user-provided value"  

======示例文件路径======
java/ql/src/Security/CWE/CWE-129/ImproperValidationOfArrayConstruction.java
======示例文件内容=======
1   public class ImproperValidationOfArrayIndex extends HttpServlet {{
2   
3     protected void doGet(HttpServletRequest request, HttpServletResponse response)
4     throws ServletException, IOException {{
5       try {{
6         // User provided value
7         int numberOfItems = Integer.parseInt(request.getParameter("numberOfItems").trim());
8
9         if (numberOfItems >= 0) {{
10          /*
11           * BAD numberOfItems may be zero, which would cause the array indexing operation to
12           * throw an ArrayIndexOutOfBoundsException
13           */
14          String items = new String[numberOfItems];
15          items[0] = "Item 1";
16        }}
17  
18        if (numberOfItems > 0) {{
19          /*
20           * GOOD numberOfItems must be greater than zero, so the indexing succeeds.
21           */
22          String items = new String[numberOfItems];
23          items[0] = "Item 1";
24        }}
25  
26      }} catch (NumberFormatException e) {{ }}
27    }}
28  }}

======你应输出=======
(bad, 1, 16)
(good, 17, 28)
++++++++++示例结束++++++++++++


"""
    user_prompt = f"""====规则文件路径===== 
{rule_path}
====规则文件内容=====
{rule_content}  

======示例文件路径======
{example_path}
======示例文件内容=======
{example_content}  
"""

    try:
        response = client.chat.completions.create(
            model=SETTINGS.llm_settings.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
        )

        output = response.choices[0].message.content.strip()

        tuples = [tuple(part.strip() for part in line.strip().split(",")) for line in output.split("\n") if line.strip()]

        return tuples
    except Exception as e:
        print(f"警告: 调用大模型失败: {e}")
        raise e


def determine_label_with_llm_without_rule_info(rule_path: str, example_path: str, goodcase: int, badcase: int):
    """
    使用大模型根据规则文件、示例文件内容确定标签

    标签原则:
    - 若由文件名或内容能判断出，该例子应能检测出漏洞，则label为"bad"
    - 若由文件名或内容能判断出，该例子不能检测出漏洞，则label为"good"
    - 若由文件名或内容不能判断出，则label为"unknown"
    - 若由文件名或内容能判断出，该例子分为多个部分，有的部分应检出漏洞，有的部分不应检出，则label为"both"
    """
    # 读取规则文件内容
    rule_content = read_file_content(rule_path)

    # 读取示例文件内容
    example_content = read_file_content(example_path, True)

    # 构造提示词
    system_prompt = f"""我需要评测Codeql规则在具体程序示例上的检测性能。一个程序示例中，有多个good,safe/bad,unsafe的代码片段作为检查点。我需要根据规则是否命中这些代码片段区间，作为Codeql规则性能的评价指标。
请根据Codeql示例文件的路径和内容，返回该示例文件中，各个代码片段检查点的区间，并返回该区间的标签。

具体要求如下：
1. 如果示例文件中，存在漏洞的代码，即使用规则检测该代码位置，Codeql应该在某个区间告警，则输出(bad, 区间起点行号， 区间终点行号)。
2. 如果示例文件中，有安全的、用以检测规则误报情况的代码，即使用规则检测该代码位置，Codeql不应该在某个区间告警，则输出(good, 区间起点行号，区间终点行号)
3. 如果示例文件中，不存在以上两种情况，或示例文件不应该对应该规则，则不返回任何内容。

请注意：good/bad 匹配点，一般存在于注释中的GOOD/BAD提示语下方。你需要精确地将这些匹配点找出来

============输出规范==============
请输出所有的匹配情况（其中，行号区间应将示例程序中的每个检查点区分开；同时这些区间的并集应尽可能覆盖整个程序，以提高规则性能评估的容错率），每行一个，例如：
(bad, 13, 18)
(bad, 19, 29)
(good, 30, 35)
(good, 36, 44)
(good, 45, 55)

++++++++++示例开始++++++++++++ 

======示例文件路径======
java/ql/src/Security/CWE/CWE-129/ImproperValidationOfArrayConstruction.java
======示例文件内容=======
1   public class ImproperValidationOfArrayIndex extends HttpServlet {{
2   
3     protected void doGet(HttpServletRequest request, HttpServletResponse response)
4     throws ServletException, IOException {{
5       try {{
6         // User provided value
7         int numberOfItems = Integer.parseInt(request.getParameter("numberOfItems").trim());
8
9         if (numberOfItems >= 0) {{
10          /*
11           * BAD numberOfItems may be zero, which would cause the array indexing operation to
12           * throw an ArrayIndexOutOfBoundsException
13           */
14          String items = new String[numberOfItems];
15          items[0] = "Item 1";
16        }}
17  
18        if (numberOfItems > 0) {{
19          /*
20           * GOOD numberOfItems must be greater than zero, so the indexing succeeds.
21           */
22          String items = new String[numberOfItems];
23          items[0] = "Item 1";
24        }}
25  
26      }} catch (NumberFormatException e) {{ }}
27    }}
28  }}

======你应输出=======
(bad, 1, 16)
(good, 17, 28)
++++++++++示例结束++++++++++++


"""
    user_prompt = f"""====规则文件路径===== 
{rule_path}

======示例文件路径======
{example_path}
======示例文件内容=======
{example_content}  
"""

    try:
        response = client.chat.completions.create(
            model=SETTINGS.llm_settings.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
        )

        output = response.choices[0].message.content.strip()

        tuples = [tuple(part.strip() for part in line.strip().split(",")) for line in output.split("\n") if
                  line.strip()]

        return tuples
    except Exception as e:
        print(f"警告: 调用大模型失败: {e}")
        raise e


def add_labels_to_examples(data: Dict[str, Any]) -> Dict[str, Any]:
    """为所有示例添加标签"""
    # labeled_data是最终生成的标签集合
    labeled_data = {}
    
    # 如果存在部分完成的结果文件，则加载它
    if os.path.exists(CODEQL_EXAMPLE_LABELED_FILE):
        try:
            labeled_data = load_json_file(CODEQL_EXAMPLE_LABELED_FILE)
            print(f"加载已存在的部分结果文件: {CODEQL_EXAMPLE_LABELED_FILE}")
        except Exception as e:
            print(f"警告: 无法加载已存在的结果文件: {e}")
            labeled_data = {}
    
    for language, rules in data.items():
        if language not in labeled_data:
            labeled_data[language] = {}
        
        for rule, rule_info in rules.items():
            # 如果规则已经处理过，检查是否所有示例都有标签
            if rule in labeled_data.get(language, {}):
                existing_examples = labeled_data[language][rule].get("examples", [])
                # 检查是否所有示例都有label
                if len(existing_examples) == 0:
                    print(f"跳过example为空的规则: {rule}")
                    continue
                if all("label" in example for example in existing_examples):
                    print(f"跳过已处理的规则: {rule}")
                    continue
            #
            # labeled_examples = []
            #
            # # 检查已存在的示例标签
            # existing_examples_dict = {}
            # if rule in labeled_data.get(language, {}):
            #     existing_examples = labeled_data[language][rule].get("examples", [])
            #     for example in existing_examples:
            #         if "label" in example:
            #             example_path = example["path"]
            #             existing_examples_dict[example_path] = example


            # 重置该rule的example列表
            labeled_data[language][rule]["examples"] = []
            # 为每个example添加标签
            for example in rule_info.get("examples", []):
                labeled_example_list = []

                example_path = example["path"]
                
                # # 如果示例已经有标签，则直接使用
                # if example_path in existing_examples_dict:
                #     labeled_examples.append(existing_examples_dict[example_path])
                #     print(f"使用已有标签: {example_path} -> {existing_examples_dict[example_path]['label']}")
                #     continue
                
                goodcase = example.get("goodcase", 0)
                badcase = example.get("badcase", 0)
                
                # 使用大模型确定标签
                label_tuples = determine_label_with_llm_without_rule_info(rule, example_path, goodcase, badcase)
                print(f"生成标签: {example_path} -> {label_tuples}")
                
                # 根据要求处理返回值
                if not label_tuples:
                    # 如果返回的列表为空
                    labeled_example_list = [{
                        "path": example_path,
                        "label": "none",
                        "interval": []
                    }]
                else:
                    # 对于每个元组，生成一个字典
                    for label_tuple in label_tuples:
                        if len(label_tuple) >= 3:
                            label_type = label_tuple[0].strip("()").strip()
                            start = label_tuple[1].strip("()").strip()
                            end = label_tuple[2].strip("()").strip()
                            labeled_example_list.append({
                                "path": example_path,
                                "label": label_type,
                                "interval": [start, end]
                            })
                
                # 每生成一个标签就保存一次
                labeled_data[language][rule]["examples"] += labeled_example_list

                print(f"生成映射: {rule} -> {labeled_example_list}\n")

                save_json_file(CODEQL_EXAMPLE_LABELED_FILE, labeled_data)
    
    return labeled_data


def main():
    """主函数"""
    print("正在加载CodeQL示例文件...")
    data = load_json_file(CODEQL_EXAMPLE_FILE)
    
    print("正在为示例添加标签...")
    labeled_data = add_labels_to_examples(data)
    
    print("正在保存带标签的CodeQL示例文件...")
    save_json_file(CODEQL_EXAMPLE_LABELED_FILE, labeled_data)
    
    print(f"已完成！带标签的文件已保存至: {CODEQL_EXAMPLE_LABELED_FILE}")


if __name__ == "__main__":
    main()