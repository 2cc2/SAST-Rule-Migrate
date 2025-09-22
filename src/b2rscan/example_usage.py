# -*- coding: utf-8 -*-
"""
B2RScan使用示例
展示如何使用规则提取器从不同SAST工具中提取规则并转换为xCPG-IR格式
"""

from b2rscan.rule_extractor import RuleExtractor, IRConverter, CodeQLRuleParser


def example_codeql_extraction():
    """
    CodeQL规则提取示例
    """
    print("=== CodeQL规则提取示例 ===")
    
    # 初始化提取器
    extractor = RuleExtractor()
    
    # 初始化解析器
    parser = CodeQLRuleParser()
    
    # 初始化IR转换器
    converter = IRConverter()
    
    # 提取CodeQL规则 (示例路径)
    codeql_path = "../../sast/codeql"
    try:
        rules = extractor.extract_codeql_rules(codeql_path)
        print(f"从CodeQL提取了 {len(rules)} 条规则")
        
        # 转换为xCPG-IR格式
        ir_rules = converter.convert(rules, "codeql")
        print(f"转换为xCPG-IR格式后有 {len(ir_rules)} 条规则")
        
        # 显示第一条规则的示例
        if ir_rules:
            print("\\n第一条规则示例:")
            print(f"ID: {ir_rules[0]['id']}")
            print(f"名称: {ir_rules[0]['name']}")
            print(f"来源: {ir_rules[0]['source']}")
            print(f"严重性: {ir_rules[0]['severity']}")
    except Exception as e:
        print(f"提取CodeQL规则时出错: {e}")


def example_rule_parsing():
    """
    规则解析示例
    """
    print("\\n=== 规则解析示例 ===")
    
    # 初始化解析器
    parser = CodeQLRuleParser()
    
    # 解析规则 (示例路径)
    codeql_path = "../../sast/codeql"
    try:
        rules = parser.parse(codeql_path)
        print(f"解析了 {len(rules)} 条规则")
        
        # 显示第一条规则
        if rules:
            print("\\n第一条解析的规则:")
            print(f"ID: {rules[0]['id']}")
            print(f"名称: {rules[0]['name']}")
    except Exception as e:
        print(f"解析规则时出错: {e}")


if __name__ == "__main__":
    example_codeql_extraction()
    example_rule_parsing()