#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
根据 ql 文件名与 example 文件名的模糊匹配程度，
将 mapping.json 中的 potential_examples 中“很像”的条目
提升到 examples。

用法：
    python promote_examples.py mapping.json mapping_updated.json
"""

import json
import sys
import re
from pathlib import Path
import difflib
from typing import List, Dict, Tuple

# 一些噪音词：Example/GOOD/BAD 等，不参与相似度计算
STOP_WORDS = {
    "example", "examples",
    "good", "bad", "gooda", "goodb", "goodc", "goodd", "goode", "goodf", "goodg",
    "case", "cases", "sample", "samples", "test", "tests",
    "ql", "js", "java", "cs", "cpp", "csharp", "b", "a", "d", "g", "o"
}


def normalize_name(path: str) -> List[str]:
    """
    将路径归一化为一组 token：
    - 取文件名（去掉扩展名）
    - 小写
    - 按 -, _, . 分词
    - 按 CamelCase 分词
    - 去掉 STOP_WORDS，去重但保持顺序
    """
    p = Path(path)
    stem = p.stem  # 文件名不含扩展名，如 ExternalAPIsUsedWithUntrustedData
    s_lower = stem.lower()

    # 用 -, _, . 作为分隔符
    s = re.sub(r"[-_.]+", " ", s_lower)

    # CamelCase 进一步拆分：
    #   ExternalAPIsUsedWithUntrustedData -> "External APIs Used With Untrusted Data"
    #   BAD -> "BAD" (连续大写字母作为一个词)
    camel = re.sub(r"(?<!^)([A-Z][a-z])", r" \1", stem)  # 匹配大写字母后跟小写字母的情况
    camel = re.sub(r"(?<!^)([A-Z])([A-Z][a-z])", r"\1 \2", camel)  # 处理连续大写字母后跟大写+小写的情况
    camel = camel.lower()

    # 合并两种拆分结果
    combined = s + " " + camel

    # 分词
    raw_tokens = combined.split()

    # 去噪 + 去重
    seen = set()
    norm_tokens: List[str] = []
    for tok in raw_tokens:
        tok = tok.strip()
        if not tok:
            continue
        # 去掉非字母数字
        tok = re.sub(r"[^a-z0-9]+", "", tok)
        if not tok:
            continue
        if tok in STOP_WORDS:
            continue
        if tok not in seen:
            seen.add(tok)
            norm_tokens.append(tok)

    return norm_tokens


def jaccard(tokens1: List[str], tokens2: List[str]) -> float:
    """token 级 Jaccard 相似度"""
    s1, s2 = set(tokens1), set(tokens2)
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)


def edit_ratio(name1: str, name2: str) -> float:
    """文件名（不含扩展名）之间的编辑距离相似度"""
    stem1 = Path(name1).stem
    stem2 = Path(name2).stem
    return difflib.SequenceMatcher(None, stem1.lower(), stem2.lower()).ratio()


def similarity(ql_path: str, example_path: str) -> float:
    """
    综合相似度：
    - 0.6 * 编辑距离相似度
    - 0.4 * token Jaccard 相似度
    """
    qt = normalize_name(ql_path)
    et = normalize_name(example_path)
    jac = jaccard(qt, et)
    er = edit_ratio(ql_path, example_path)
    return 0.8 * er + 0.2 * jac


def promote_examples_for_query(
    ql_path: str,
    info: Dict,
    high: float = 0.70,
    mid: float = 0.45,
) -> Dict:
    """
    对单个 ql 条目做提升：
    - 输入：{"examples": [...], "potential_examples": [...]}
    - 输出：更新后的同结构 dict
    """
    examples: List[str] = info.get("examples", [])[:]
    potential: List[str] = info.get("potential_examples", [])[:]

    if not potential:
        # 没有候选，直接返回
        return {
            "examples": examples,
            "potential_examples": potential,
        }

    scores: List[Tuple[str, float]] = []
    for ex in potential:
        s = similarity(ql_path, ex)
        scores.append((ex, s))

    # 按相似度从高到低排序
    scores.sort(key=lambda x: x[1], reverse=True)

    # 根据阈值划分
    strong: List[str] = []
    weak: List[str] = []

    for ex, s in scores:
        if s >= high:
            strong.append(ex)
        elif s >= mid:
            weak.append(ex)
        # s < mid 的直接丢弃

    # 这里策略可以按需求调：
    # 1. 所有 strong 都提升到 examples
    # 2. weak 保留在 potential_examples
    # 3. s < mid 的从 mapping 中移除（认为关系不大）

    new_examples = examples[:]
    for ex in strong:
        if ex not in new_examples:
            new_examples.append(ex)

    new_potential: List[str] = weak[:]  # 只保留 weak
    return {
        "examples": new_examples,
        "potential_examples": new_potential,
    }


def process_mapping(mapping: Dict, high: float = 0.70, mid: float = 0.45) -> Dict:
    """
    对整个 mapping 做处理：
    {
        "path/to/query.ql": {
            "examples": [...],
            "potential_examples": [...]
        },
        ...
    }
    """
    new_mapping: Dict[str, Dict] = {}
    for ql_path, info in mapping.items():
        if not isinstance(info, dict):
            # 防御性检查
            new_mapping[ql_path] = info
            continue

        updated = promote_examples_for_query(
            ql_path,
            info,
            high=high,
            mid=mid,
        )
        new_mapping[ql_path] = updated

    return new_mapping


def main():
    if len(sys.argv) != 3:
        print("用法: python promote_examples.py <input_json> <output_json>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    new_mapping = process_mapping(mapping)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(new_mapping, f, indent=2, ensure_ascii=False)

    print(f"已写入更新后的映射到: {output_path}")


if __name__ == "__main__":
    main()
