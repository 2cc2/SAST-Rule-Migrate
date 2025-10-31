import os
import re
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(project_root)
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from agent.llm_client import LLM
from prompt.migrate import MigratePrompt, RepairPrompt, AbstractPrompt
from runnable_valid.codeql import validate_codeql_rule

lock = threading.Lock()  # 控制台输出锁，防止多线程日志混乱

Language = "Java"

def thread_print(msg: str):
    """线程安全打印"""
    with lock:
        print(f"[{threading.current_thread().name}] {msg}")


def get_rule_from_llm(response: str) -> str:
    matches = re.findall(r"```ql\n(.*?)```", response, re.DOTALL)
    if matches:
        thread_print("✔ 成功提取 Markdown 中的 QL 代码块")
        return matches[0].strip()
    else:
        thread_print("❌ 未找到符合格式的 QL 代码块")
        return ""


def save_rule(yaml_text: str, output_dir: str, base_name: str = "semgrep_rule"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.ql")
    with open(file_path, "w") as f:
        f.write(yaml_text)
    thread_print(f"✔ 规则已保存到 {file_path}")


def save_IR(yaml_text: str, output_dir: str, base_name: str = "semgrep_rule"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.ir")
    with open(file_path, "w") as f:
        f.write(yaml_text)
    thread_print(f"✔ IR 已保存到 {file_path}")


def load_rule_from_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        thread_print(f"❌ 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()
    thread_print(f"✔ 成功从文件 {file_path} 加载内容")
    return yaml_content.strip()


def get_all_yaml_files(directory):
    yaml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yaml"):
                yaml_files.append(os.path.join(root, file))
    return yaml_files


def migrate_rule(input_file: str, output_dir: str, log_dir: str, sast: str = "Codeql", max_retries: int = 5):
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
        verbose=False
    )

    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    thread_print(f"🚀 开始处理: {input_filename}")

    IR_contet = load_rule_from_file(input_file)
    if not IR_contet:
        return
    log_file = os.path.join(log_dir, f"{input_filename}.log")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    prompt = MigratePrompt().format(IR=IR_contet, language=Language, target_SAST=sast)
    for attempt in range(1, max_retries + 1):
        thread_print(f"🔁 第 {attempt} 次尝试生成规则...")
        thread_print(f"prompt{prompt}")
        print("="*40)
        response = llm.Transform(prompt=prompt, max_tokens=3000)
        thread_print(response)
        rule_content = get_rule_from_llm(response)
        if not rule_content:
            thread_print("⚠️ 未找到规则内容，尝试调整提示词重试...")
            continue
        
        result = validate_codeql_rule(rule_content)
        
        if result["valid"]:
            thread_print("✅ 验证通过，保存结果...")
            save_rule(rule_content, output_dir, base_name=input_filename)
            llm.clear_context()
            return
        else:
            thread_print(f"🙅 验证失败：{result['error']}")
            file_path=os.path.join(log_dir, f"{input_filename}_attempt{attempt}.yaml")
            save_rule(rule_content, log_dir, base_name=file_path)
        with open(log_file, "a") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"Timestamp: {timestamp}\n")
            log.write(f"Attempt: {attempt}\n")
            log.write(f"Error: {result['error']}\n")
            log.write(f"Rule Content:\n{rule_content}\n")
            log.write(f"{'=' * 80}\n")
            log.write(f"Prompt:\n{prompt}\n")
            log.write(f"{'=' * 80}\n")

            # 生成修复建议
            prompt = AbstractPrompt().format(code=rule_content, error=result['error'], language=Language, sast=sast)
            advise = llm.Transform(prompt=prompt, max_tokens=3000)
            prompt = RepairPrompt().format(code=rule_content, language=Language, error=result['error'], sast=sast, advise=advise)
            time.sleep(2)

    thread_print("🚫 多次尝试仍未成功，请人工干预。")
    llm.clear_context()


def process_multiple_files(directory: str, output_dir: str, log_dir: str, max_workers: int = 10):
    output_files = os.listdir(output_dir)
    print(f"[📂] 输出目录已有 {len(output_files)} 个文件")

    yaml_files = get_all_yaml_files(directory)
    # yaml_files = yaml_files[:1]
    print(f"[📄] 待迁移 YAML 文件数: {len(yaml_files)}")

    existing = [os.path.splitext(f)[0].split('_')[0] for f in os.listdir(output_dir)]
    print(f"[✅] 已存在规则数量: {len(existing)}")

    tasks = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for file in yaml_files:
            base_name = os.path.splitext(os.path.basename(file))[0]
            if base_name in existing:
                print(f"[⏩] 跳过已存在文件: {base_name}")
                continue
            future = executor.submit(migrate_rule, file,output_dir, log_dir)
            tasks.append(future)
            thread_print(f"🧠 已提交任务: {file}")

        for future in as_completed(tasks):
            try:
                future.result()
            except Exception as e:
                thread_print(f"❌ 任务出错: {e}")


if __name__ == "__main__":
    input_directory = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/IrBase/JavaIR"
    output_directory = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/output/Semgrep2/CodeQL/JAVA2"
    log_directory = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/log/codeqlJAVAlog2"

    for d in [input_directory,output_directory, log_directory]:
        os.makedirs(d, exist_ok=True)

    start = datetime.now()
    process_multiple_files(input_directory, output_directory, log_directory, max_workers=20)
    end = datetime.now()

    print(f"\n✅ 全部任务完成，总耗时: {end - start}")