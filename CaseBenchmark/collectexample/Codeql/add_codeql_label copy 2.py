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
import logging
from typing import Dict, Any, List
from openai import OpenAI  # 假设使用OpenAI或兼容的API

# 配置文件路径
CODEQL_EXAMPLE_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_examples.json"
CODEQL_EXAMPLE_LABELED_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example_labeled.json"
CODEQL_ROOT = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql"

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 初始化OpenAI客户端
# client = OpenAI(
#     api_key=os.environ.get("LLM_API_KEY"),
#     base_url="https://4.0.wokaai.com/v1/chat/completions"
# )


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

def extract_samples_from_examples(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """从JSON数据中提取examples中的samples"""
    all_examples = []
    for language, rules in data.items():
        print(f"处理语言: {language}")
        for rule, rule_info in rules.items():
            examples = rule_info.get("examples", [])
            print(f"规则 {rule} 提取到 {len(examples)} 个 examples")
            all_examples.extend(examples)
    return all_examples
    #         for example in examples:
    #             example_samples = example.get("samples", [])
    #             samples.extend(example_samples)
    # return samples

# def add_labels_to_samples(data: Dict[str, Any]) -> Dict[str, Any]:
#     """为所有示例的samples添加标签"""
#     for language, rules in data.items():
#         for rule, rule_info in rules.items():
#             examples = rule_info.get("examples", [])
#             for example in examples:
#                 samples = example.get("samples", [])
#                 for sample in samples:
#                     # 根据某些条件为每个sample添加标签
#                     # 这里假设一个简单的逻辑：如果代码中包含"secure"，则为"good"，否则为"bad"
#                     code = sample.get("code", "")
#                     if "secure" in code.lower():
#                         sample["label"] = "good"
#                     else:
#                         sample["label"] = "bad"
#     return data



# def add_labels_to_samples(data: Dict[str, Any]) -> Dict[str, Any]:
#     """为所有示例的samples添加标签，并标记StartLine和EndLine"""
#     for language, rules in data.items():
#         for rule, rule_info in rules.items():
#             examples = rule_info.get("examples", [])
#             for example in examples:
#                 samples = example.get("samples", [])
#                 for sample in samples:
#                     code = sample.get("code", "")
#                     lines = code.splitlines()  # 按行分割代码
#                     start_line = None
#                     end_line = None
#                     label = None

#                     for i, line in enumerate(lines, start=1):  # 遍历每一行，行号从1开始
#                         if "GOOD" in line:
#                             if label:  # 如果之前有标签，结束当前标签
#                                 end_line = i - 1
#                                 sample["label"] = label
#                                 sample["StartLine"] = start_line
#                                 sample["EndLine"] = end_line
#                             # 开始新的标签
#                             label = "good"
#                             start_line = i
#                         elif "BAD:" in line:
#                             if label:  # 如果之前有标签，结束当前标签
#                                 end_line = i - 1
#                                 sample["label"] = label
#                                 sample["StartLine"] = start_line
#                                 sample["EndLine"] = end_line
#                             # 开始新的标签
#                             label = "bad"
#                             start_line = i

#                     # 如果最后一行仍有未结束的标签
#                     if label:
#                         sample["label"] = label
#                         sample["StartLine"] = start_line
#                         sample["EndLine"] = len(lines)
#     return data


def generate_labels_for_sample(code: str) -> List[Dict[str, Any]]:
    """为单个样本生成标签，支持大小写不敏感匹配"""
    labels = []
    start_line = None
    label = None

    lines = code.splitlines()  # 按行分割代码
    for i, line in enumerate(lines, start=1):  # 遍历每一行，行号从1开始
        line_lower = line.lower()  # 转为小写以支持大小写不敏感匹配
        if "good" in line_lower:
            if label:  # 如果之前有标签，结束当前标签
                labels.append({
                    "label": label,
                    "StartLine": start_line,
                    "EndLine": i - 1
                })
            label = "good"
            start_line = i
        elif "bad" in line_lower:
            if label:  # 如果之前有标签，结束当前标签
                labels.append({
                    "label": label,
                    "StartLine": start_line,
                    "EndLine": i - 1
                })
            label = "bad"
            start_line = i

    # 如果最后一行仍有未结束的标签
    if label:
        labels.append({
            "label": label,
            "StartLine": start_line,
            "EndLine": len(lines)
        })

    return labels


def add_labels_to_samples(data: Dict[str, Any]) -> (Dict[str, Any], List[Dict[str, Any]]):
    """为所有示例的samples添加标签，并标记StartLine和EndLine，同时统计未标记的规则"""
    unlabeled_rules = []  # 用于存储未标记的规则

    for language, rules in data.items():
        for rule, rule_info in rules.items():
            examples = rule_info.get("examples", [])
            rule_unlabeled = False  # 标记当前规则是否有未标记的样本

            for example in examples:
                samples = example.get("samples", [])
                for sample in samples:
                    code = sample.get("code", "")
                    labels = generate_labels_for_sample(code)  # 使用新函数生成标签

                    # 如果没有生成任何标签，标记当前规则未标记
                    if not labels:
                        rule_unlabeled = True
                        sample["unlabeled_reason"] = "No GOOD or BAD keywords found"

                    # 将所有标签存储到 sample 中
                    sample["labels"] = labels

            # 如果当前规则有未标记的样本，将整个规则添加到未标记规则列表
            if rule_unlabeled:
                unlabeled_rules.append({
                    "language": language,
                    "rule": rule,
                    "rule_info": rule_info
                })

    return data, unlabeled_rules

def save_unlabeled_rules(unlabeled_rules: List[Dict[str, Any]]) -> None:
    """保存未标记规则到文件"""
    if unlabeled_rules:
        unlabeled_rules_path = os.path.join(os.path.dirname(CODEQL_EXAMPLE_LABELED_FILE), "unlabeled_rules.json")
        save_json_file(unlabeled_rules_path, unlabeled_rules)
        logging.warning(f"未标记的规则已保存至: {unlabeled_rules_path}")
    else:
        logging.info("所有规则均已成功标记！")

def main():
    """主函数"""
    logging.info("正在加载CodeQL示例文件...")
    data = load_json_file(CODEQL_EXAMPLE_FILE)

    logging.info("正在为samples添加标签...")
    labeled_data, unlabeled_rules = add_labels_to_samples(data)

    logging.info("正在保存带标签的CodeQL示例文件...")
    save_json_file(CODEQL_EXAMPLE_LABELED_FILE, labeled_data)

    # 输出未标记的规则到JSON文件
    save_unlabeled_rules(unlabeled_rules)

    logging.info(f"已完成！带标签的文件已保存至: {CODEQL_EXAMPLE_LABELED_FILE}")

if __name__ == "__main__":
    main()