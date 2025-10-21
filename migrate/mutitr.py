import os
import re
import time
from datetime import datetime
from sast_tools.semgrep import validate_semgrep_rule
from agent.llm_client import LLM
from agent.prompt.sastprompt import TransformPrompt, RepairPrompt,AbstractPrompt
def get_rule_from_llm(response: str) -> str:
    """
    从 LLM 响应中提取 Markdown 格式的规则内容。
    确保返回的内容符合 SemgrepPrompt 的输出格式。
    """
    # 提取 Markdown 中的代码块内容
    matches = re.findall(r"```yaml\n(.*?)```", response, re.DOTALL)
    if matches:
        print("[✔] 成功提取 Markdown 中的 YAML 代码块")
        return matches[0].strip()
    else:
        print("[❌] 未找到符合格式的 YAML 代码块")
        return ""

# 保存规则到 output 文件夹
def save_rule(yaml_text: str,output_dir:str, base_name: str = "semgrep_rule"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.yml")
    with open(file_path, "w") as f:
        f.write(yaml_text)
    print(f"[✔] 规则已保存到 {file_path}")

def load_rule_from_file(file_path: str) -> str:
    """
    从指定文件中加载 YAML 规则内容。
    :param file_path: 文件路径
    :return: YAML 规则内容字符串
    """
    if not os.path.exists(file_path):
        print(f"[❌] 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()
    print(f"[✔] 成功从文件 {file_path} 加载规则内容")
    return yaml_content.strip()

def migrate_rule(input_file: str, output_dir: str, log_dir: str, sast: str = "Semgrep", max_retries: int = 2):
    """
    迁移单个规则文件。
    :param input_file: 输入的 .go 文件路径
    :param output_dir: 保存规则的输出目录
    :param log_dir: 保存日志的目录
    :param sast: SAST 工具名称
    :param max_retries: 最大重试次数
    """
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
        verbose=True
    )
    # 加载代码内容
    if not os.path.exists(input_file):
        print(f"[❌] 文件 {input_file} 不存在")
        return

    test_code = load_rule_from_file(input_file)
    if not test_code:
        print(f"[❌] 无法加载文件 {input_file}")
        return
    example = load_rule_from_file("/Users/djoker/Desktop/CTGA/demo/semgrep.txt")
    # 定义输入的 prompt 和代码
    prompt = TransformPrompt().format(code=test_code, language="go", sast=sast,example=example)
    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    log_file = os.path.join(log_dir, f"{input_filename}.log")
    output_file = os.path.join(output_dir, f"{input_filename}.yml")

    # 自动创建日志和输出目录
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    for attempt in range(1, max_retries + 1):
        print(f"\n🔄 第 {attempt} 次尝试生成规则...")
        response = llm.Transform(prompt=prompt, max_tokens=3000)
        print(f"[📜] LLM 响应内容：\n{response}")
        rule_content = get_rule_from_llm(response)
        if not rule_content:
            print("[❌] 未找到代码块内容，尝试更新提示词...")
            prompt += " 请确保包含 markdown 格式的 yaml 代码块（```yaml ... ```）"
            continue

        result = validate_semgrep_rule(rule_content)
        if result["valid"]:
            print("[✅] 规则验证通过！")
            save_rule(rule_content, output_dir,base_name=input_filename)
            llm.clear_context()  # 清除上下文，保留系统提示
            break
        else:
            print(f"[🙅] 验证失败：{result['error']}")
            with open(log_file, "a") as log:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"Timestamp: {timestamp}\n")
                log.write(f"Attempt: {attempt}\n")
                log.write(f"Error: {result['error']}\n")
                log.write(f"Rule Content:\n{rule_content}\n")
                log.write(f"Prompt:\n{prompt}\n")
                log.write(f"{'=' * 80}\n")
            prompt = AbstractPrompt().format(code=rule_content, error=result['error'].strip(),  language="go", sast=sast)
            advise= llm.Transform(prompt=prompt, max_tokens=3000)
            prompt = RepairPrompt().format(code=rule_content, language="go", error=result['error'].strip(), sast=sast,advise=advise)
            time.sleep(5)  # 避免过快请求
            print("[🔄] 正在重新生成规则...")
            print(f"当前提示词：{prompt}")
    else:
        print("[🚫] 多次尝试仍未成功生成有效规则，请人工干预。")
        llm.clear_context()


def process_multiple_files(directory: str, output_dir: str, log_dir: str):
    """
    处理指定目录中的所有 .go 文件。
    :param directory: 输入目录，包含 .go 文件
    :param output_dir: 保存规则的输出目录
    :param log_dir: 保存日志的目录
    """
    go_files = [f for f in os.listdir(directory) if f.endswith(".go")]
    print(f"[📂] 找到 {len(go_files)} 个 .go 文件：{go_files}")

    for go_file in go_files:
        file_path = os.path.join(directory, go_file)
      
        print(f"\n[🔄] 正在处理文件：{file_path}")
        migrate_rule(file_path, output_dir, log_dir)


if __name__ == "__main__":
    input_directory = "/Users/djoker/Desktop/CTGA/demo/input/gosec/rules"  # 替换为你的 .go 文件目录
    output_directory = "/Users/djoker/Desktop/CTGA/demo/output/gosec_3"
    log_directory = "/Users/djoker/Desktop/CTGA/demo/codeerror/gosec2semgrep_3"

    process_multiple_files(input_directory, output_directory, log_directory)