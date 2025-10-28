
import os
import re
import time
from datetime import datetime
from sast_tools.muticodeql import validate_codeql_rule
from agent.llm_client import LLM
from agent.prompt.codeql import IRPrompt,IRTransformPrompt, RepairPrompt,AbstractPrompt
def get_rule_from_llm(response: str) -> str:
    """
    从 LLM 响应中提取 Markdown 格式的规则内容。
    确保返回的内容符合 SemgrepPrompt 的输出格式。
    """
    # 提取 Markdown 中的代码块内容
    matches = re.findall(r"```ql\n(.*?)```", response, re.DOTALL)
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
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.mql")
    with open(file_path, "w") as f:
        f.write(yaml_text)
    print(f"[✔] 规则已保存到 {file_path}")
def save_IR(yaml_text: str,output_dir:str, base_name: str = "semgrep_rule"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.ir")
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

def get_all_java_files(directory):
    java_files = []
    for root, _, files in os.walk(directory):  # 使用 os.walk 遍历目录及子目录
        for file in files:
            if file.endswith(".yaml"):  # 检查文件后缀是否为 .java
                java_files.append(os.path.join(root, file))  # 保存文件的完整路径
    return java_files

def migrate_rule(input_file: str,IR_dir:str, output_dir: str, log_dir: str, sast: str = "Codeql", max_retries: int = 3):
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
    input_filename = os.path.splitext(os.path.basename(input_file))[0]
   

    example = load_rule_from_file("/Users/djoker/Desktop/CTGA/demo/migrate/codeql.txt")
    IR_file = os.path.join(IR_dir, f"{input_filename}.ir")
    log_file = os.path.join(log_dir, f"{input_filename}.log")
    output_file = os.path.join(output_dir, f"{input_filename}.ql")
    #获取中间表示
    IR_prompt=IRPrompt().format(code=test_code)
    
    # 自动创建日志和输出目录
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(IR_dir, exist_ok=True)
    print(f"提取IR")
    IR_content = llm.ExtIR(prompt=IR_prompt, max_tokens=3000)
    prompt = IRTransformPrompt().format(IR=IR_content, language="java", sast=sast,example=example)
    for attempt in range(1, max_retries + 1):
        print(f"\n🔄 第 {attempt} 次尝试生成规则...")
        response = llm.Transform(prompt=prompt, max_tokens=3000)
        print(f"[📜] LLM 响应内容：\n{response}")
        rule_content = get_rule_from_llm(response)
        if not rule_content:
            print("[❌] 未找到代码块内容，尝试更新提示词...")
            prompt += " 请确保包含 markdown 格式的 yaml 代码块（```ql ... ```）"
            continue

        result = validate_codeql_rule(rule_content, language="java")
        if result["valid"]:
            print("[✅] 规则验证通过！")
            save_IR(IR_content, IR_dir,base_name=input_filename)
            save_rule(rule_content, output_dir,base_name=input_filename)
            llm.clear_context()  # 清除上下文，保留系统提示
            break
        else:
            print(f"[🙅] 验证失败：{result['error']}")
            with open(log_file, "a") as log:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"Timestamp: {timestamp}\n")
                log.write(f"Attempt: {attempt}\n")
                log.write(f"IR Content:\n{IR_content}\n")
                log.write(f"Error: {result['error']}\n")
                log.write(f"Rule Content:\n{rule_content}\n")
                # log.write(f"Prompt:\n{prompt}\n")
                log.write(f"{'=' * 80}\n")
            prompt = AbstractPrompt().format(code=rule_content, error=result['error'].strip(),  language="java", sast=sast)
            advise= llm.Transform(prompt=prompt, max_tokens=3000)
            prompt = RepairPrompt().format(code=rule_content, language="java", error=result['error'].strip(), sast=sast,advise=advise)
            time.sleep(2)  # 避免过快请求
            print("[🔄] 正在重新生成规则...")
            print(f"当前提示词：{prompt}")
    else:
        print("[🚫] 多次尝试仍未成功生成有效规则，请人工干预。")
        llm.clear_context()


def process_multiple_files(directory: str,IR:str, output_dir: str, log_dir: str):
    """
    处理指定目录中的所有 .go 文件。
    :param directory: 输入目录，包含 .go 文件
    :param output_dir: 保存规则的输出目录
    :param log_dir: 保存日志的目录
    """

# 获取 output_dir 文件夹中的文件数量
    output_files = os.listdir(output_dir)
    output_file_count = len(output_files)
    print(f"[📂] 输出文件夹中共有 {output_file_count} 个文件")
    java_files = get_all_java_files(directory)
    print(f"[📂] 找到 {len(java_files)} 个")
    for java_file in java_files:
        file_path = os.path.join(directory, java_file)
        print(f"\n[🔄] 正在处理文件：{file_path}")
        base_name= os.path.splitext(os.path.basename(java_file))[0]

        print(f"[📂] 处理文件：{base_name}")
        # 检查输出目录中是否已经存在包含该文件名的文件
        existing_files = [f for f in os.listdir(output_dir) if base_name in f]
        
        if existing_files:
            print(f"[⏩] 文件 {base_name} 的规则已存在，跳过处理 {file_path}")
            continue
        migrate_rule(file_path, IR,output_dir, log_dir)
  
if __name__ == "__main__":
    input_directory = "/home/cbb/SAST-Rule-Migrate/input/semgrep/java"  
    IR_directory = "/home/cbb/SAST-Rule-Migrate/IR_V4/" 
    output_directory = "/home/cbb/SAST-Rule-Migrate/output/semgrep2codeql_IR_v4"

    log_directory = "/home/cbb/SAST-Rule-Migrate/codeerror/semgrep2codeql_IRv4"
    for directory in [input_directory, output_directory, log_directory]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"[✅] 目录已创建: {directory}")
        else:
            print(f"[✔] 目录已存在: {directory}")
    process_multiple_files(input_directory,IR_directory,output_directory, log_directory)