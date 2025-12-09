import xml.etree.ElementTree as ET

def extract_samples_from_xml(file_path):
    # 解析 XML 文件
    tree = ET.parse(file_path)
    root = tree.getroot()

    # 提取 <sample> 标签内容
    samples = []
    for sample in root.findall(".//sample"):
        src = sample.get("src")  # 获取 src 属性
        language = sample.get("language")  # 获取 language 属性（如果有）
        code = sample.text.strip() if sample.text else None  # 获取标签内的代码内容
        samples.append({"src": src, "language": language, "code": code})

    return samples
def extract_examples_from_xml(file_path):
    # 解析 XML 文件
    tree = ET.parse(file_path)
    root = tree.getroot()

    # 提取 <example> 标签内容
    examples = []
    for example in root.findall(".//example"):
        example_content = {"description": [], "samples": []}
        print(ET.tostring(example, encoding='unicode'))  # 打印整个 <example> 标签内容
        for child in example:
            if child.tag == "description":
                example_content["description"].append(child.text.strip() if child.text else "")
            elif child.tag == "sample":
                src = child.get("src")
                language = child.get("language")
                code = child.text.strip() if child.text else None
                example_content["samples"].append({"src": src, "language": language, "code": code})
        examples.append(example_content)
    return examples
# 使用示例
file_path = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/go/ql/src/Security/CWE-089/StringBreak.qhelp"  # 替换为你的 XML 文件路径
examples = extract_examples_from_xml(file_path)
print("Extracted Examples:")
print(examples)
# 打印结果
for example in examples:
    print(f"Description: {example['description']}")
    for sample in example['samples']:
        print(f" Sample src: {sample['src']}, language: {sample['language']}, code: {sample['code']}")
