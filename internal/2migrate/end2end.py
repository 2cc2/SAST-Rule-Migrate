import os
import re
import sys
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# 假设这些模块路径是正确的，且存在于项目中
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(project_root)
from agent.llm_client import LLM # 假设存在
from prompt.end2end import MigratePrompt, RepairPrompt, AbstractPrompt # 假设存在
from runnable_valid.semgrep import validate_semgrep_rule

# ==============================================================================
# 🎯 可配置参数 (CONSTANTS)
# ==============================================================================

# 语言设置
LANGUAGE = "Java"

# 目标 SAST 工具
TARGET_SAST = "Semgrep" 
SOURCE_SAST ="Codeql"
target_ext="yaml"
# LLM 配置
LLM_MODEL = "deepseek-v3"
LLM_SYSTEM_PROMPT = "You are a skilled vulnerability detection rule designer."
MAX_TOKENS = 3000

# 迁移尝试配置
MAX_RETRIES = 5

# 多线程配置
MAX_WORKERS = 1

# 文件路径配置 (请根据实际情况修改这些路径)
# 注意：在 __main__ 块中，这些路径通常会被实际赋值，但在此处作为示例配置
INPUT_DIR_EXAMPLE = "/home/cbb/SAST-Rule-Migrate/internal/2migrate/runnable_valid"
OUTPUT_DIR_EXAMPLE = "SAST-Rule-Migrate/output/CWE-20"
LOG_DIR_EXAMPLE = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/log/CWE-20"

# ==============================================================================
# 辅助函数
# ==============================================================================

lock = threading.Lock()  # 控制台输出锁，防止多线程日志混乱

def thread_print(msg: str):
    """线程安全打印"""
    with lock:
        print(f"[{threading.current_thread().name}] {msg}")


def get_rule_from_llm(response: str) -> str:
    """从 LLM 响应中提取 QL 代码块"""
    matches = re.findall(r"```yaml\n(.*?)```", response, re.DOTALL)
    if matches:
        thread_print("✔ 成功提取 Markdown 中的 QL 代码块")
        return matches[0].strip()
    else:
        thread_print("❌ 未找到符合格式的 QL 代码块")
        return ""


def save_rule(rule_text: str, output_dir: str, base_name: str):
    """保存生成的 QL 规则文件"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    # 文件后缀名直接使用 .ql
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.yml")
    with open(file_path, "w") as f:
        f.write(rule_text)
    thread_print(f"✔ 规则已保存到 {file_path}")


def save_IR(ir_text: str, output_dir: str, base_name: str):
    """保存 IR 文件 (此函数在您的原代码中未被调用，但保留)"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{base_name}_{timestamp}.ir")
    with open(file_path, "w") as f:
        f.write(ir_text)
    thread_print(f"✔ IR 已保存到 {file_path}")


def load_rule_from_file(file_path: str) -> str:
    """从文件加载规则内容"""
    if not os.path.exists(file_path):
        thread_print(f"❌ 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()
    thread_print(f"✔ 成功从文件 {file_path} 加载内容")
    return yaml_content.strip()


def get_all_rule_files(directory):
    """递归获取目录下所有 .yaml 文件"""
    rule_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 兼容 .yaml 和 .yml
            if file.endswith((".ql")): 
                rule_files.append(os.path.join(root, file))
    return rule_files

# ==============================================================================
# 核心业务逻辑
# ==============================================================================

def migrate_rule(input_file: str, output_dir: str, log_dir: str):
    """
    单个规则文件的迁移、验证和修复循环。
    参数配置已使用全局常量。
    """
    llm = LLM(
        system_prompt=LLM_SYSTEM_PROMPT,
        model=LLM_MODEL,
        verbose=False
    )

    # 使用常量
    max_retries = MAX_RETRIES 
    target_sast = TARGET_SAST
    language = LANGUAGE

    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    thread_print(f"🚀 开始处理: {input_filename}")

    # 加载 IR 内容 (原始 Semgrep 规则)
    IR_contet = load_rule_from_file(input_file)
    if not IR_contet:
        return

    # 准备日志和输出目录
    log_file = os.path.join(log_dir, f"{input_filename}.log")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    # 初始迁移提示
    prompt = MigratePrompt().format(test_code=IR_contet, language=language, source_SAST=SOURCE_SAST,target_SAST=target_sast,target_ext=TARGET_SAST)

    for attempt in range(1, max_retries + 1):
        thread_print(f"🔁 第 {attempt} 次尝试生成规则...")
        thread_print(f"prompt:\n{prompt[:200]}...") # 打印部分 prompt
        print("="*40)
        
        # 调用 LLM 进行转换
        response = llm.Transform(prompt=prompt, max_tokens=MAX_TOKENS)
        thread_print(response[:500] + "...") # 打印部分响应
        
        rule_content = get_rule_from_llm(response)
        if not rule_content:
            thread_print("⚠️ 未找到规则内容，尝试调整提示词重试...")
            llm.clear_context() # 清理 LLM 上下文，确保下一次尝试是全新的
            # 重新使用最初的 MigratePrompt 进行重试，防止陷入 LLM 幻觉
            prompt = MigratePrompt().format(test_code=IR_contet, language=language, target_SAST=target_sast)
            continue
        
        # 验证生成的 CodeQL 规则
        result = validate_semgrep_rule(rule_content)
        
        if result["valid"]:
            # 成功
            thread_print("✅ 验证通过，保存结果...")
            save_rule(rule_content, output_dir, base_name=input_filename)
            llm.clear_context()
            return
        else:
            # 失败，进行修复尝试
            thread_print(f"🙅 验证失败：{result['error']}")
            
            # 1. 保存失败的规则内容到日志目录
            failed_rule_base_name = f"{input_filename}_attempt{attempt}"
            save_rule(rule_content, log_dir, base_name=failed_rule_base_name)
            
            # 2. 写入日志文件，记录错误信息、原始规则和 Prompt
            with open(log_file, "a") as log:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"Timestamp: {timestamp}\n")
                log.write(f"Attempt: {attempt}\n")
                log.write(f"Error: {result['error']}\n")
                log.write(f"Rule Content:\n{rule_content}\n")
                log.write(f"{'=' * 80}\n")
                
                # 3. 生成修复提示 (Abstract -> Repair)
                
                # a. 生成抽象修复建议 (AbstractPrompt)
                abstract_prompt = AbstractPrompt().format(code=rule_content, error=result['error'], language=language, sast=target_sast)
                advise = llm.Transform(prompt=abstract_prompt, max_tokens=MAX_TOKENS)
                
                # b. 构造带建议的修复提示 (RepairPrompt)
                repair_prompt = RepairPrompt().format(code=rule_content, language=language, error=result['error'], sast=target_sast, advise=advise)
                
                # 将修复相关的上下文也写入日志
                log.write(f"Abstract Prompt:\n{abstract_prompt}\n")
                log.write(f"{'-' * 40}\n")
                log.write(f"Repair Prompt:\n{repair_prompt}\n")
                log.write(f"{'=' * 80}\n\n")

                # 更新 prompt 为修复提示，用于下一次循环
                prompt = repair_prompt
                
                time.sleep(2) # 避免 API 调用过于频繁

    # 达到最大重试次数仍未成功
    thread_print("🚫 多次尝试仍未成功，请人工干预。")
    llm.clear_context()


def process_multiple_files(directory: str, output_dir: str, log_dir: str):
    """
    多线程处理多个规则文件。
    多线程配置已使用全局常量。
    """
    max_workers = MAX_WORKERS
    
    # 统计已完成文件
    output_files = os.listdir(output_dir)
    print(f"[📂] 输出目录已有 {len(output_files)} 个文件")

    # 获取所有待处理文件
    rule_files = get_all_rule_files(directory)
    print(f"[📄] 待迁移 QL 文件数: {len(rule_files)}")
    rule_files=rule_files[:1]
    print(f"[📄] 待迁移 QL 文件数: {len(rule_files)}")
    # 找出已存在（已成功迁移）的规则
    # 规则命名格式为 base_name_timestamp.ql
    existing = set()
    for f in os.listdir(output_dir):
        if f.endswith(".ql"):
            # 提取文件名中第一个 '_' 之前的部分作为 base_name
            base_name = f.split('_')[0]
            existing.add(base_name)
    
    print(f"[✅] 已存在规则数量: {len(existing)}")

    tasks = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for file in rule_files:
            base_name = os.path.splitext(os.path.basename(file))[0]
            
            # 跳过已存在的任务
            if base_name in existing:
                print(f"[⏩] 跳过已存在文件: {base_name}")
                continue
            
            # 提交任务
            future = executor.submit(migrate_rule, file, output_dir, log_dir)
            tasks.append(future)
            thread_print(f"🧠 已提交任务: {file}")

        # 监控任务完成情况
        for future in as_completed(tasks):
            try:
                future.result() # 捕获线程执行中的异常
            except Exception as e:
                thread_print(f"❌ 任务出错: {e}")


# ==============================================================================
# 主执行块
# ==============================================================================

if __name__ == "__main__":
    # 在主块中为目录变量赋值，并使用上面定义的示例路径
    # 实际运行时，可以根据命令行参数或配置文件读取这些路径
    input_directory = INPUT_DIR_EXAMPLE
    output_directory = OUTPUT_DIR_EXAMPLE
    log_directory = LOG_DIR_EXAMPLE

    for d in [input_directory, output_directory, log_directory]:
        os.makedirs(d, exist_ok=True)

    print(f"--- 规则迁移开始 ---")
    print(f"语言: {LANGUAGE}, 目标 SAST: {TARGET_SAST}, LLM: {LLM_MODEL}")
    print(f"最大线程数: {MAX_WORKERS}, 最大重试次数: {MAX_RETRIES}")
    print(f"输入目录: {input_directory}")
    print(f"输出目录: {output_directory}")
    print(f"日志目录: {log_directory}")
    print(f"--------------------")

    start = datetime.now()
    process_multiple_files(input_directory, output_directory, log_directory)
    end = datetime.now()

    print(f"\n✅ 全部任务完成，总耗时: {end - start}")