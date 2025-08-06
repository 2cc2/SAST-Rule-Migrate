import os
import re
import pandas as pd
from sast_tools.semgrep import validate_semgrep_rule
from agent.llm_client import LLM
from datetime import datetime
from agent.prompt.sastprompt import TransformPrompt, RepairPrompt
import time
import tiktoken 
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
def save_rule(yaml_text: str, base_name: str = "semgrep_rule"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("output", exist_ok=True)
    file_path = os.path.join("output", f"{base_name}_{timestamp}.yml")
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
# 主流程
def main():
    SAST="Semgrep"

    MAX_RETRIES = 3
    
    # 初始化 LLM 实例
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.", 
        model="deepseek-v3", 
        verbose=True
    )
    # 定义文件路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(current_dir, "input/gosec/rules/hardcoded_credentials.go")

    test_code = load_rule_from_file(input_file)
    #  定义输入的 prompt 和代码
    prompt =TransformPrompt().format(code=test_code,language="go",sast= SAST)
    # 提取 input_file 的最后文件名（不含扩展名）
    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    log_file = f"/Users/djoker/Desktop/CTGA/demo/codeerror/{input_filename}.log"
    response_file = f"/Users/djoker/Desktop/CTGA/demo/response/{input_filename}.yml"
    # 自动创建日志文件（如果不存在）
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))
    if not os.path.exists(os.path.dirname( response_file)):
        os.makedirs(os.path.dirname( response_file))
    # log_file = "/Users/djoker/Desktop/CTGA/demo/codeerror/semgrep_errors.log"
    # response = llm.Transform(prompt=prompt, max_tokens=3000)
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n🔄 第 {attempt} 次尝试生成规则...")
        response = llm.Transform(prompt=prompt, max_tokens=3000)

        with open(response_file, "w") as f:
            f.write("--------------\n")
            f.write(response)
        rule_content = get_rule_from_llm(response)
        # print("[✔] 成功提取 Markdown 内容",rule_content)
   
        # rule_content = load_rule_from_file("/Users/djoker/Desktop/CTGA/demo/output/gpt.yml")
        if not rule_content:
            print("[❌] 未找到代码块内容，尝试更新提示词...")
            prompt += " 请确保包含 markdown 格式的 yaml 代码块（```yaml ... ```）"
            continue
        result = validate_semgrep_rule(rule_content)
        if result["valid"]:
            print("[✅] 规则验证通过！")
            save_rule(rule_content, base_name=SAST)
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
            # print("[💡] 大模型建议：", advise)
            prompt = RepairPrompt().format(code=rule_content,language="go",error=result['error'].strip(),sast= SAST)
            time.sleep(5)  # 避免过快请求
            print("[🔄] 正在重新生成规则...")
            print(f"当前提示词：{prompt}")
    else:
        print("[🚫] 多次尝试仍未成功生成有效规则，请人工干预。")

if __name__ == "__main__":
    main()