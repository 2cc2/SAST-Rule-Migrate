#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试规则提取功能的简单脚本
"""

import os
import sys
from src.b2rscan.task.rule_extraction.extractor import RuleExtractor

def main():
    # 创建规则提取器实例
    extractor = RuleExtractor()
    
    # 测试用的示例规则路径（如果存在）
    test_path = "sast/codeql"
    if os.path.exists(test_path):
        print(f"正在从 {test_path} 提取CodeQL规则...")
        rules = extractor.extract_rules("codeql", test_path)
        print(f"提取到 {len(rules)} 条规则")
        if rules:
            print("第一条规则预览:")
            print(rules[0])
    else:
        print(f"测试路径 {test_path} 不存在，跳过测试")

if __name__ == "__main__":
    main()