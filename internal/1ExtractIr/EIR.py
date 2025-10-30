
import os
import re
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from agent.llm_client import LLM
from prompt.IR import IRPrompt


lock = threading.Lock()  # 控制台输出锁，防止多线程日志混乱


def thread_print(msg: str):
    """线程安全打印"""
    with lock:
        print(f"[{threading.current_thread().name}] {msg}")

def migrate_rule(input_file: str, IR_dir: str, output_dir: str, log_dir: str, sast: str = "Codeql", max_retries: int = 20):
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
        verbose=False
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
    prompt = IRTransformPrompt().format(IR=IR_content, language="python", sast=sast,example=example)
        
    for attempt in range(1, max_retries + 1):
        thread_print(f"🔁 第 {attempt} 次尝试生成规则...")
        if attempt % 5 ==0:
            IR_prompt = IRPrompt().format(code=test_code)
            thread_print("⏳ 正在提取 IR ...")
            IR_content = llm.ExtIR(prompt=IR_prompt, max_tokens=3000)
            prompt = IRTransformPrompt().format(IR=IR_content, language="python", sast=sast,example=example)
        thread_print(prompt)
        response = llm.Transform(prompt=prompt, max_tokens=3000)
        thread_print(response)
        rule_content = get_rule_from_llm(response)
        if not rule_content:
            thread_print("⚠️ 未找到规则内容，尝试调整提示词重试...")
            continue
        
        result = validate_codeql_rule(rule_content, language="python")
        
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
                log.write(f"Timestamp: {timestamp}\n")
                log.write(f"Attempt: {attempt}\n")
                log.write(f"Prompt:\n{prompt}\n")
                log.write(f"Error: {result['error']}\n")
                log.write(f"Rule Content:\n{rule_content}\n")
                log.write(f"{'=' * 80}\n")

            # 生成修复建议
            prompt = AbstractPrompt().format(code=rule_content, error=result['error'], language="python", sast=sast)
            advise = llm.Transform(prompt=prompt, max_tokens=3000)
            prompt = RepairPrompt().format(code=rule_content, language="python", error=result['error'], sast=sast, advise=advise)
            time.sleep(2)

    thread_print("🚫 多次尝试仍未成功，请人工干预。")
    llm.clear_context()


def process_multiple_files(directory: str, IR_dir: str, output_dir: str, log_dir: str, max_workers: int = 10):
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
    input_directory = "/home/cbb/SAST-Rule-Migrate/input/semgrep/python_classified_rules/CWE-22"
    IR_directory = "/home/cbb/SAST-Rule-Migrate/Py22"
    log_directory = "/home/cbb/SAST-Rule-Migrate/codeerror/Py22"

    for d in [input_directory, IR_directory,log_directory]:
        os.makedirs(d, exist_ok=True)

    start = datetime.now()
    process_multiple_files(input_directory, IR_directory, output_directory, log_directory, max_workers=10)
    end = datetime.now()

    print(f"\n✅ 全部任务完成，总耗时: {end - start}")