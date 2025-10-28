import os
import re
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from sast_tools.muticodeql import validate_codeql_rule,ensure_dir
from agent.llm_client import LLM
from agent.prompt.codeql import IRTransformPrompt, RepairPrompt, AbstractPrompt
from agent.prompt.IR import IRPrompt


lock = threading.Lock()  # 控制台输出锁，防止多线程日志混乱


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


def migrate_rule(input_file: str, IR_dir: str, output_dir: str, log_dir: str, sast: str = "Codeql", max_retries: int = 5):
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
        verbose=True
    )

    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    thread_print(f"🚀 开始处理: {input_filename}")

    test_code = load_rule_from_file(input_file)
    if not test_code:
        return

    example = load_rule_from_file("/Users/djoker/Desktop/CTGA/demo/codeql.txt")
    IR_file = os.path.join(IR_dir, f"{input_filename}.ir")
    log_file = os.path.join(log_dir, f"{input_filename}.log")

    os.makedirs(IR_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    # Step 1: 生成中间表示
    IR_prompt = IRPrompt().format(code=test_code)
    thread_print("⏳ 正在提取 IR ...")
    IR_content = llm.ExtIR(prompt=IR_prompt, max_tokens=3000)

    for attempt in range(1, max_retries + 1):
        thread_print(f"🔁 第 {attempt} 次尝试生成规则...")
        prompt = IRTransformPrompt().format(IR=IR_content, language="java", sast=sast, example=example)
        response = llm.Transform(prompt=prompt, max_tokens=3000)

        rule_content = get_rule_from_llm(response)
        if not rule_content:
            thread_print("⚠️ 未找到规则内容，尝试调整提示词重试...")
            continue
        
        result = validate_codeql_rule(rule_content, language="java")
        
        # result = validate_codeql_rule(rule_content)
        if result["valid"]:
            thread_print("✅ 验证通过，保存结果...")
            save_IR(IR_content, IR_dir, base_name=input_filename)
            save_rule(rule_content, output_dir, base_name=input_filename)
            llm.clear_context()
            return
        else:
            thread_print(f"🙅 验证失败：{result['error']}")
            with open(log_file, "a") as log:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"Timestamp: {timestamp}\nAttempt: {attempt}\nError: {result['error']}\n{'=' * 80}\n")

            # 生成修复建议
            prompt = AbstractPrompt().format(code=rule_content, error=result['error'], language="java", sast=sast)
            advise = llm.Transform(prompt=prompt, max_tokens=3000)
            repair_prompt = RepairPrompt().format(code=rule_content, language="java", error=result['error'], sast=sast, advise=advise)
            llm.Transform(prompt=repair_prompt, max_tokens=3000)
            time.sleep(2)

    thread_print("🚫 多次尝试仍未成功，请人工干预。")
    llm.clear_context()


def process_multiple_files(directory: str, IR_dir: str, output_dir: str, log_dir: str, max_workers: int = 3):
    output_files = os.listdir(output_dir)
    print(f"[📂] 输出目录已有 {len(output_files)} 个文件")

    yaml_files = get_all_yaml_files(directory)
    # yaml_files = yaml_files[:5]
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
            future = executor.submit(migrate_rule, file, IR_dir, output_dir, log_dir)
            tasks.append(future)
            thread_print(f"🧠 已提交任务: {file}")

        for future in as_completed(tasks):
            try:
                future.result()
            except Exception as e:
                thread_print(f"❌ 任务出错: {e}")


if __name__ == "__main__":
    input_directory = "/home/cbb/SAST-Rule-Migrate/input/semgrep/java_classified_rules"
    IR_directory = "/home/cbb/SAST-Rule-Migrate/JAVA_XCPGIR5"
    output_directory = "/home/cbb/SAST-Rule-Migrate/output/JAVA_semgrep2codeql_XCPGIR_5cwe"
    log_directory = "/home/cbb/SAST-Rule-Migrate/codeerror/JAVA_semgrep2codeql_XCPGIR_5cwe"

    for d in [input_directory, IR_directory, output_directory, log_directory]:
        os.makedirs(d, exist_ok=True)

    start = datetime.now()
    process_multiple_files(input_directory, IR_directory, output_directory, log_directory, max_workers=10)
    end = datetime.now()

    print(f"\n✅ 全部任务完成，总耗时: {end - start}")