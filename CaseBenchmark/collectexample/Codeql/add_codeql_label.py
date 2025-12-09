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


def generate_labels_for_sample(code: str, src: str) -> List[Dict[str, Any]]:
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
    
    # 如果代码中没有找到"good"或"bad"，检查文件名是否包含"good"或"bad"
    # if not labels and src:
    #     src_lower = src.lower()  # 转为小写以支持大小写不敏感匹配
    #     if "good" in src_lower:
    #         labels.append({
    #             "label": "good",
    #             "StartLine": 1,
    #             "EndLine": len(lines),
    #             "ALLFILE_CASE":""
    #         })
    #     elif "bad" in src_lower:
    #         labels.append({
    #             "label": "bad",
    #             "StartLine": 1,
    #             "EndLine": len(lines),
    #             "ALLFILE_CASE":""
    #         })
        # 如果代码中没有找到"good"或"bad"，通过与大模型交互来获得"good"或"bad"的行号
    if not labels:
        try:
            # 假设有一个函数 interact_with_model 用于与大模型交互
            model_response = interact_with_model(code)
            for label_info in model_response:
                labels.append({
                    "label": label_info["label"],
                    "StartLine": label_info["StartLine"],
                    "EndLine": label_info["EndLine"]
                })
        except Exception as e:
            logging.error(f"与大模型交互时出错: {e}")


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
                    src = sample.get("src", "")  # 获取样本的文件路径
                    labels = generate_labels_for_sample(code, src)  # 使用新函数生成标签
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

def save_sample_paths(unlabeled_rules: List[Dict[str, Any]]) -> None:
    """保存未标记样例的路径到单独的文件"""
    sample_paths = []
    for rule in unlabeled_rules:
        rule_info = rule.get("rule_info", {})
        examples = rule_info.get("examples", [])
        for example in examples:
            samples = example.get("samples", [])
            for sample in samples:
                src = sample.get("src", "")
                if src:
                    sample_paths.append(src)

    if sample_paths:
        sample_paths_file = os.path.join(os.path.dirname(CODEQL_EXAMPLE_LABELED_FILE), "unlabeled_sample_paths.txt")
        with open(sample_paths_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(sample_paths))
        logging.warning(f"未标记样例的路径已保存至: {sample_paths_file}")
    else:
        logging.info("未标记样例中没有路径信息！")

def interact_with_model(code: str) -> List[Dict[str, Any]]:
    """
    与大模型交互以获取代码中的标签信息。
    假设返回的结果是一个包含标签信息的列表，每个标签信息包括：
    - label: 标签名称（如"good"或"bad"）
    - StartLine: 标签开始的行号
    - EndLine: 标签结束的行号
    """
    try:
        # 自定义提示词（prompt），将未标记的代码样本发送给大模型
        prompt = (
            "以下是一个代码样本，请分析代码并标注其中的安全性标签。"
            "如果代码片段是安全的，请标记为'good'；如果代码片段是不安全的，请标记为'bad'。"
            "请返回每个标签的起始行号和结束行号。代码如下：\n\n"
            f"{code}"
        )

        # 调用大模型接口
        response = client.Completion.create(
            model="deepseek-v3",  # 假设使用GPT-4模型
            prompt=prompt,
            max_tokens=500,
            temperature=0.2
        )

        # 解析大模型的响应
        labels = json.loads(response["choices"][0]["text"].strip())
        return labels  # 返回一个包含标签信息的列表

    except Exception as e:
        logging.error(f"调用大模型时发生错误: {e}")
        return []

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

    # 输出未标记样例的路径到单独的文件
    save_sample_paths(unlabeled_rules)

    logging.info(f"已完成！带标签的文件已保存至: {CODEQL_EXAMPLE_LABELED_FILE}")

if __name__ == "__main__":
    main()