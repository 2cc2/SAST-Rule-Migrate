#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
转换脚本，用于给semgrep示例添加标签

该脚本读取semgrep_example.json文件，对每条规则的"examples"列表中的每个example，
读取文件内容并匹配特定模式，生成包含路径、标签和行号的字典。
"""

import json
import os
import re
from typing import List, Tuple


def load_json_file(filepath: str) -> dict:
    """加载JSON文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(filepath: str, data: dict) -> None:
    """保存JSON文件"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def read_file_lines(filepath: str) -> List[str]:
    """读取文件内容，返回行列表，如果文件不存在或无法读取则返回空列表"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        print(f"警告: 无法读取文件 {filepath}: {e}")
        return []


def match_patterns_in_file(filepath: str):
    """
    匹配文件中的模式：
    - 匹配"ruleid:"，并记录行号
    - 匹配以"ok:"为核心的注释模式，并记录行号
    
    返回: List[Tuple[str, int]]，元组格式为(标签, 行号)
    """
    lines = read_file_lines(filepath)
    if not lines:
        return []
    
    results = []
    
    # 匹配各种语言的注释模式 (如 // ok: rule-name 或 # ok: rule-name)
    # 匹配规则更宽松，支持不同形式的注释
    ok_pattern = re.compile(r'.*[#/\*].*\bok\s*:\s*[\w\-]+', re.IGNORECASE)
    ruleid_pattern = re.compile(r'.*\bruleid\s*:\s*[\w\-]+', re.IGNORECASE)
    
    for line_no, line in enumerate(lines, 1):
        # 匹配ruleid模式 (应该标记为 bad)
        if ruleid_pattern.search(line):
            results.append(("bad", line_no))
        
        # 匹配ok模式 (应该标记为 good)
        if ok_pattern.search(line):
            results.append(("good", line_no))

    final_results = []

    for i, result in enumerate(results):

        if i == len(results) - 1:
            final_results.append((result[0], result[1], -1))
            break

        final_results.append((result[0], result[1], results[i + 1][1]))

    return final_results


def process_example_file(example_path: str, semgrep_root: str) -> List[dict]:
    """
    处理单个示例文件，生成标签字典列表
    
    Args:
        example_path: 示例文件路径
        semgrep_root: semgrep规则根目录
        
    Returns:
        List[dict]: 包含路径、标签和行号的字典列表
    """
    if example_path.startswith('\\'):
        example_path = example_path[1:]
    
    full_path = os.path.join(semgrep_root, example_path)
    matches = match_patterns_in_file(full_path)
    
    # 如果没有匹配项，返回none标签
    if not matches:
        return [{
            "path": example_path,
            "label": "none",
            "line_no": "none"
        }]
    
    # 为每个匹配项生成字典
    result = []
    for label, start, end in matches:
        result.append({
            "path": example_path,
            "label": label,
            "interval": (start, end)
        })
    
    return result


def process_semgrep_examples(input_file: str, output_file: str, semgrep_root: str):
    """
    处理semgrep示例文件，添加标签
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        semgrep_root: semgrep规则根目录
    """
    # 加载原始数据
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    labeled_data = {}
    
    # 遍历所有语言
    for language, rules in data.items():
        labeled_data[language] = {}
        
        # 遍历所有规则
        for rule, rule_data in rules.items():
            labeled_data[language][rule] = {"examples": []}
            
            # 处理每个示例
            for example in rule_data.get("examples", []):
                # 处理示例文件
                example_results = process_example_file(example, semgrep_root)
                
                # 添加到结果中
                labeled_data[language][rule]["examples"].extend(example_results)
                
                for result in example_results:
                    print(f"已处理 {language} {rule} {example} --> {result['label']}:{result['interval']}")
            
            # 及时保存结果，实现"interrupt-robust"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(labeled_data, f, indent=2, ensure_ascii=False)
    
    print(f"处理完成，结果已保存到 {output_file}")


if __name__ == "__main__":
    # 配置文件路径
    SEMGREP_EXAMPLE_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/SemgrepSample/semgrep_sample.json"
    SEMGREP_EXAMPLE_LABELED_FILE = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/SemgrepSample/semgrep_example_labeled.json"
    SEMGREP_ROOT ="/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/semgrep-rules"

    # 处理示例文件
    process_semgrep_examples(SEMGREP_EXAMPLE_FILE, SEMGREP_EXAMPLE_LABELED_FILE, SEMGREP_ROOT)