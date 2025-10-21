import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import os
import yaml  # 用于处理 YAML 文件
from tqdm import tqdm
from dotenv import load_dotenv
from agent.llm_client import LLM, Model
from prompt.IR import SourcePrompt,SinkPrompt,SanitazerPrompt,PropagationPrompt
import re
from collections import OrderedDict
# from finder import find_context

# 加载环境变量
load_dotenv()

RULES_DIR = "/Users/djoker/Desktop/CTGA/demo/preprocess/input/python"
OUTPUT_YAML_PATH = "/Users/djoker/Desktop/CTGA/demo/preprocess/output/sink"
VISITED_LOG_PATH = "visited_log.txt"
PROMPTS_LOG_PATH = "prompts_log.txt"


def parse_rule_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return content

def get_rule_from_llm(response: str) -> str:
    matches = re.findall(r"```yaml\n(.*?)```", response, re.DOTALL)
    if matches:
        print("[✔] 成功提取 Markdown 中的 YAML 代码块")
        return matches[0].strip()
    else:
        print("[❌] 未找到符合格式的 YAML 代码块")
        return ""

def save_to_file(file_path, content):
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(content + "\n")

def batch_process_rules():

    rule_files = []
    # 遍历 RULES_DIR，筛选前 5 个 .yaml 文件
    for root, _, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith(".yaml"):
                rule_files.append(os.path.join(root, f))
        if len(rule_files) >= 5:  # 只处理前 5 个文件
            rule_files = rule_files[:5]
            break   
    print(f"[✔] 共找到 {len(rule_files)} 个规则文件")
    
    llm = LLM(system_prompt="你是静态分析工具漏洞检测规则编写大师",
              model=Model.DEEPSEEK_V3.value,
              verbose=True)
    results = []  # 保存所有规则结果
    
    for idx, file in enumerate(tqdm(rule_files, desc="Processing Rules")):
        raw_name = os.path.splitext(os.path.basename(file))[0]
        rule_text = parse_rule_file(file)
       
        # prompt= SourcePrompt().format(code=rule_text.strip())
        prompt= SinkPrompt().format(code=rule_text.strip())
        # prompt= SanitazerPrompt().format(code=rule_text.strip())
        # prompt= PropagationPrompt().format(code=rule_text.strip())
        save_to_file(PROMPTS_LOG_PATH, f"Prompt for {file}:\n{prompt}")
        try:
            response = llm.Transform(prompt)
            save_to_file("response_log.txt", f"Response for {file}:\n{response}")
            extracted_yaml = get_rule_from_llm(response)
            if extracted_yaml:
                rule_yaml = yaml.safe_load(extracted_yaml)
                # print(f"[✔] 成功解析 YAML: {file}")
                # rule_yaml["filename"] = file
                # rule_yaml["id"] = raw_name
                print(f"[✔] 成功解析 JSON: {file}")
                ordered_rule_yaml = OrderedDict()
                ordered_rule_yaml["id"] = raw_name
                ordered_rule_yaml.update(rule_yaml)
                results.append(ordered_rule_yaml)
                output_file_path = os.path.join(
                    os.path.dirname(OUTPUT_YAML_PATH), f"{raw_name}.yaml"
                )
                print(f"[✔] 正在保存规则到 {output_file_path}...")
                with open(output_file_path, "w", encoding="utf-8") as f:
                    yaml.dump(rule_yaml, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                print(f"[✔] 已保存到 {output_file_path}")
            else:
                print(f"[❌] 响应: {response}")
        except yaml.YAMLError:
            print(f"[⚠️] YAML 解析错误: {file}")
        except Exception as e:
            print(f"[⚠️] 处理文件 {file} 时出错: {e}")

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT_YAML_PATH), exist_ok=True)
    batch_process_rules()