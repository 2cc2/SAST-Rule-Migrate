
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
from prompt.IR import IRPrompt,ValidatePrompt,RethinkPrompt


lock = threading.Lock()  # 控制台输出锁，防止多线程日志混乱

def thread_print(msg: str):
    """线程安全打印"""
    with lock:
        print(f"[{threading.current_thread().name}] {msg}")

def get_rule_from_llm(response: str) -> str:
    """
    从 LLM 的响应中提取 QL 代码块。
    参数:
        response (str): LLM 返回的字符串响应，可能包含 Markdown 格式的 QL 代码块。
    返回:
        str: 提取的 QL 代码块内容。如果未找到符合格式的代码块，返回空字符串。
    """
    matches = re.findall(r"```ql\n(.*?)```", response, re.DOTALL)
    if matches:
        thread_print("✔ 成功提取 Markdown 中的 QL 代码块")
        return matches[0].strip()
    else:
        thread_print("❌ 未找到符合格式的 QL 代码块")
        return ""

def save_rule(yaml_text: str, output_dir: str, file_name: str):
    """
    将规则内容保存为 .ql 文件。
    参数:
        yaml_text (str): 要保存的规则内容。
        output_dir (str): 保存文件的目标目录。
        base_name (str): 文件的基础名称，默认为 "semgrep_rule"。
    返回:
        None
    """
    os.makedirs(output_dir, exist_ok=True)  # 确保目标目录存在
    file_path = os.path.join(output_dir, file_name)  # 构造文件路径
    with open(file_path, "w") as f:
        f.write(yaml_text)  # 写入规则内容
    thread_print(f"✔ 规则已保存到 {file_path}")

def save_IR(yaml_text: str, output_dir: str, base_name: str):
    """
    将中间表示 (IR) 内容保存为 .yaml 文件。
    参数:
        yaml_text (str): 要保存的 IR 内容。
        output_dir (str): 保存文件的目标目录。
        base_name (str): 文件的基础名称，默认为 "semgrep_rule"。

    返回:
        None
    """
    os.makedirs(output_dir, exist_ok=True)  # 确保目标目录存在
    file_path = os.path.join(output_dir, f"{base_name}.yaml")  # 构造文件路径
    with open(file_path, "w") as f:
        f.write(yaml_text)  # 写入 IR 内容
    thread_print(f"✔ IR 已保存到 {file_path}")

def load_rule_from_file(file_path: str) -> str:
    """
    从文件中加载规则内容。

    参数:
        file_path (str): 要加载的文件路径。

    返回:
        str: 文件中的规则内容。如果文件不存在，返回空字符串。
    """
    if not os.path.exists(file_path):  # 检查文件是否存在
        thread_print(f"❌ 文件 {file_path} 不存在")
        return ""
    with open(file_path, "r") as f:
        yaml_content = f.read()  # 读取文件内容
    thread_print(f"✔ 成功从文件 {file_path} 加载内容")
    return yaml_content.strip()

def get_yaml_files(directory):
    """
    获取指定目录及其子目录中所有 .yaml 文件的路径。

    参数:
        directory (str): 要搜索的目录路径。

    返回:
        list: 包含所有 .yaml 文件路径的列表。
    """
    yaml_files = []
    for root, _, files in os.walk(directory):  # 遍历目录及子目录
        for file in files:
            if file.endswith(".yaml"):  # 检查文件扩展名
                yaml_files.append(os.path.join(root, file))  # 添加文件路径到列表
    return yaml_files

def IRGenerate(input_file: str, IR_dir: str, log_dir: str, sast: str = "Semgrep", max_retries: int = 10):
    llm = LLM(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
        verbose=False
    )

    input_filename = os.path.splitext(os.path.basename(input_file))[0]
    thread_print(f"🚀 开始处理: {input_filename}")
    origin_code = load_rule_from_file(input_file)

    if not origin_code:
        return

    IR_file = os.path.join(IR_dir, f"{input_filename}.ir")
    log_file = os.path.join(log_dir, f"{input_filename}.log")
    os.makedirs(IR_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    
    prompt = IRPrompt().format(code=origin_code,SAST=sast, language="python")
    for attempt in range(1, max_retries + 1):
        thread_print(f"🔁 第 {attempt} 次尝试生成规则...")
        # if attempt%5 ==0:
        #     promt = IR_prompt
        thread_print("⏳ 正在提取 IR ...")
        IR_content = llm.ExtIR(prompt=prompt, max_tokens=3000)
        print(IR_content)
        validate_prompt = ValidatePrompt().format(Code=origin_code , language="python", SAST=sast, IR_content=IR_content)
        result = llm.Transform(prompt=validate_prompt, max_tokens=3000)
        
        if "Yes" in result:
            thread_print("✅ 验证通过，保存结果...")
            save_IR(IR_content, IR_dir, base_name=input_filename)
            llm.clear_context()
            return
        else:
            prompt = RethinkPrompt().format(Error=result,IR_content=IR_content, language="python", SAST=sast) 
            file_path=os.path.join(log_dir, f"{input_filename}_attempt{attempt}.yaml")
            save_IR(IR_content, IR_dir, base_name=file_path)
        with open(log_file, "a") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"Timestamp: {timestamp}\n")
            log.write(f"Attempt: {attempt}\n")
            log.write(f"IR Content:\n{IR_content}\n")
            log.write(f"Valid: {result}\n")
            log.write(f"{'=' * 80}\n")
            log.write(f"prompt:\n{prompt}\n")
            log.write(f"{'=' * 80}\n")
    thread_print("🚫 多次尝试仍未成功，请人工干预。")
    llm.clear_context()


def process_multiple_files(directory: str, IR_dir: str, log_dir: str, max_workers: int = 10):
    output_files = os.listdir(IR_dir)
    print(f"[📂] IR目录已有 {len(output_files)} 个文件")
    #TODO 改成多种工具支持的
    yaml_files = get_yaml_files(directory)
    
    print(f"[📄] 待迁移 YAML 文件数: {len(yaml_files)}")
    #具体设计文件名字更改
    existing = [os.path.splitext(f)[0].split('_')[0] for f in os.listdir(IR_dir)]
    print(f"[✅] 已存在规则数量: {len(existing)}")

    tasks = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for file in yaml_files:
            base_name = os.path.splitext(os.path.basename(file))[0]
            if base_name in existing:
                print(f"[⏩] 跳过已存在文件: {base_name}")
                continue
            future = executor.submit(IRGenerate, file, IR_dir, log_dir)
            tasks.append(future)
            thread_print(f"🧠 已提交任务: {file}")

        for future in as_completed(tasks):
            try:
                future.result()
            except Exception as e:
                thread_print(f"❌ 任务出错: {e}")


if __name__ == "__main__":
    input_directory = "/home/cbb/SAST-Rule-Migrate/input/semgrep/java_classified_rules/"
    IR_directory = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/IrBase/JavaIR"
    log_directory = "/home/cbb/SAST-Rule-Migrate/internal/labsuit/log/JavaIR"

    for d in [input_directory, IR_directory,log_directory]:
        os.makedirs(d, exist_ok=True)

    start = datetime.now()
    process_multiple_files(input_directory, IR_directory, log_directory, max_workers=20)
    end = datetime.now()

    print(f"\n✅ 全部任务完成，总耗时: {end - start}")