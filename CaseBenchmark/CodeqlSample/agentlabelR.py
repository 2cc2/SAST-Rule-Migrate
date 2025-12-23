import json
import os
import copy
import time
import atexit
import hashlib
from openai import OpenAI

# =========================================================
# 主题颜色
# =========================================================
class Theme:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'  # Agent 专用颜色
    RESET = '\033[0m'
    BOLD = '\033[1m'

# =========================================================
# Agent 配置
# =========================================================
client = OpenAI(
    api_key="sk-4a14b8f4281a4418856120d1515bfde0",
    base_url="https://api.deepseek.com"
)

# =========================================================
# Agent 自动重试
# =========================================================
_original_create = client.chat.completions.create

def retrying_create(*args, **kwargs):
    max_retry = 5
    for attempt in range(1, max_retry + 1):
        try:
            return _original_create(*args, **kwargs)
        except Exception as e:
            wait = attempt * 2
            print(f"[RETRY] Agent 调用失败，第 {attempt} 次，{wait}s 后重试: {e}")
            time.sleep(wait)
    raise RuntimeError("Agent 多次失败，已放弃")

client.chat.completions.create = retrying_create

# =========================================================
# checkpoint 机制
# =========================================================
CHECKPOINT_FILE = "checkpoint.json"

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return set()
                return set(json.loads(content).get("done_ids", []))
        except json.JSONDecodeError:
            print(f"[WARN] {CHECKPOINT_FILE} 内容无效，已重置")
            return set()
    return set()

def save_checkpoint(done_ids):
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump({"done_ids": list(done_ids)}, f, indent=2)
DONE_IDS = load_checkpoint()
# 使用稳定 SHA256 哈希
def sample_id_from_code(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8')).hexdigest()



@atexit.register
def persist_checkpoint():
    save_checkpoint(DONE_IDS)

# =========================================================
# 给代码加行号
# =========================================================
def add_line_numbers(code: str) -> str:
    lines = code.splitlines()
    numbered_lines = [f"{i+1:3} | {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)

# =========================================================
# 调用大模型获取标注建议
# =========================================================
def get_llm_suggestion(rule_name, code):
    numbered_code = add_line_numbers(code)
    prompt=f"""
你是一个精确的代码安全标注助手（DeepSeek），任务是分析 Java 代码样例并进行行级标注。

要求:
1.识别符合规则 "{rule_name}" 的 Bad (漏洞/不规范) 和 Good (修复/规范) 区间。
2. 对代码中违反规则的区间判定“bad”。
3. 对代码中修复或符合规则的片段判定为 "good"。
4. 给每一行自动编号从 1 开始。
5.标注请尽量精确完整。
6. 仅输出 JSON，严格遵守格式：
{{
    "reasoning": "简短描述分析过程",
    "commands": ["bad 起始行 结束行", "good 起始行 结束行","bad 起始行 结束行","good 起始行 结束行",....]
}}
7. 不要输出任何多余文字或解释。

Java 代码如下:
{numbered_code}

请根据上述要求，返回 JSON。
"""

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "你是一个精确的代码安全标注助手，只输出 JSON。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={'type': 'json_object'}
        )
        content = response.choices[0].message.content.strip()
        return json.loads(content)
    except Exception as e:
        return {"reasoning": f"Agent 调用失败: {e}", "commands": []}

# =========================================================
# 手动标注工具
# =========================================================
def manual_annotate(lines, existing_labels, info_header, agent_suggest=None):
    new_labels = []

    if agent_suggest and agent_suggest.get("commands"):
        for cmd in agent_suggest["commands"]:
            try:
                parts = cmd.split()
                lbl, start, end = parts[0], int(parts[1]), int(parts[2])
                new_labels.append({"label": lbl, "StartLine": start, "EndLine": end})
            except:
                pass
    else:
        new_labels = copy.deepcopy(existing_labels)

    while True:
        new_labels.sort(key=lambda x: x["StartLine"])
        print("\033[H\033[J", end="")
        print(f"{Theme.BOLD}{Theme.BLUE}=== 标注助手 (DeepSeek 协作模式) === {info_header}{Theme.RESET}")

        if agent_suggest:
            print(f"{Theme.MAGENTA}[Agent 推理]: {agent_suggest['reasoning']}{Theme.RESET}")
            print(f"{Theme.MAGENTA}[Agent 指令]: {', '.join(agent_suggest['commands'])}{Theme.RESET}")

        print("-" * 60)
        for i, line in enumerate(lines, 1):
            color, tag = "", ""
            for lb in new_labels:
                if lb["StartLine"] <= i <= lb["EndLine"]:
                    color = Theme.RED if lb["label"] == "bad" else Theme.GREEN
                    tag = f"[{lb['label'].upper()}]"
                    break
            print(f"{Theme.YELLOW}{i:3}{Theme.RESET} | {color}{tag:10} {line}{Theme.RESET}")

        print(f"\n{Theme.BLUE}操作指令:{Theme.RESET}")
        print(f"  - 's': {Theme.GREEN}确认并保存{Theme.RESET} | 'clear': 清空 | 'q': 退出")
        # print("  - 'r': 重新调用大模型重新标注")
        print("  - 手动修改: 'bad 5 10' 或 'good 15 20'")

        cmd = input(f"\n{Theme.BOLD}>> {Theme.RESET}").strip().lower()

        if cmd == 's':
            return new_labels
        elif cmd == 'q':
            return None
        elif cmd == 'clear':
            new_labels = []
        elif cmd == "sq":
            return new_labels
        # elif cmd == 'r':
        #     rule_name = info_header.split("规则: ")[-1]
        #     example_path = info_header.split("")
        #     agent_suggest = get_llm_suggestion(rule_name, "\n".join(lines))
        #     new_labels = []
        #     if agent_suggest and agent_suggest.get("commands"):
        #         for cmd2 in agent_suggest["commands"]:
        #             try:
        #                 parts = cmd2.split()
        #                 lbl, start, end = parts[0], int(parts[1]), int(parts[2])
        #                 new_labels.append({"label": lbl, "StartLine": start, "EndLine": end})
        #             except:
        #                 pass
        else:
            try:
                parts = cmd.split()
                if len(parts) == 3:
                    lbl, start, end = parts[0], int(parts[1]), int(parts[2])
                    new_labels = [lb for lb in new_labels if not (lb["StartLine"] <= end and lb["EndLine"] >= start)]
                    new_labels.append({"label": lbl, "StartLine": start, "EndLine": end})
            except:
                input("格式错误，回车继续...")

# =========================================================
# 包装 manual_annotate 完成即记录断点
# =========================================================
_original_manual_annotate = manual_annotate

def wrapped_manual_annotate(lines, labels, info, agent_suggest):
    result = _original_manual_annotate(lines, labels, info, agent_suggest)
    if result is not None:
        sha256=sample_id_from_code("\n".join(lines))
        DONE_IDS.add(sample_id_from_code("\n".join(lines)))

        print(f"SHA已保存{sha256}")
    return result

manual_annotate = wrapped_manual_annotate

# =========================================================
# 主程序
# =========================================================
def main():
    input_path = "codeql_example_labeled.json"
    output_path = "codeql_example_manual_fixed.json"
    log_path = "agent_log.jsonl"

    if not os.path.exists(input_path):
        print(f"错误: 找不到文件 {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    sample_queue = []
    skipped_count = 0
    if "java" in data:
        for rule_name, rule_content in data["java"].items():
            if isinstance(rule_content, dict) and "examples" in rule_content:
                for example in rule_content["examples"]:
                    for sample in example.get("samples", []):
                        sid = sample_id_from_code("\n".join(sample.get("code", "").splitlines()))
                        # sha256=sample_id_from_code("\n".join(lines))
                        src_path = sample.get("src", "N/A")  # 获取路径
                        if sid in DONE_IDS:
                            skipped_count += 1
                            print(f"[已跳过] 规则 {rule_name} 样本 {sid}")
                            continue
                        sample_queue.append({
                            "rule": rule_name,
                            "data_ref": sample,
                            "is_unlabeled": len(sample.get("labels", [])) == 0,
                            "src": src_path
                        })

    print(f"\n总计 {skipped_count} 个样本已标注，{len(sample_queue)} 个待标注。\n")
    sample_queue.sort(key=lambda x: x["is_unlabeled"], reverse=True)

    for idx, item in enumerate(sample_queue, 1):
        sample = item["data_ref"]
        code = sample.get("code", "")


        print(f"\n{Theme.MAGENTA}[{idx}/{len(sample_queue)}] Agent 正在分析规则: {item['rule']} ...{Theme.RESET}")
        suggestion = get_llm_suggestion(item["rule"], code)

        with open(log_path, 'a', encoding='utf-8') as lf:
            lf.write(json.dumps({"idx": idx, "rule": item['rule'], "suggestion": suggestion}, ensure_ascii=False) + "\n")

        info = f"进度: {idx}/{len(sample_queue)} | 规则: {item['rule']} || 路径: {item['src']}"
        # ===========================
        # 新增：自动检查 LLM 标签是否和原标签一致
        # ===========================
        original_labels = sample.get("labels", [])
        llm_labels = []
        if suggestion.get("commands"):
            for cmd in suggestion["commands"]:
                try:
                    parts = cmd.split()
                    lbl, start, end = parts[0], int(parts[1]), int(parts[2])
                    llm_labels.append({"label": lbl, "StartLine": start, "EndLine": end})
                except:
                    pass

        # 如果原标签和 LLM 建议一致，则跳过人工标注
        def labels_equal(a, b):
            if len(a) != len(b):
                return False
            a_sorted = sorted(a, key=lambda x: (x["StartLine"], x["EndLine"], x["label"]))
            b_sorted = sorted(b, key=lambda x: (x["StartLine"], x["EndLine"], x["label"]))
            return a_sorted == b_sorted

        if labels_equal(original_labels, llm_labels):
            print(f"{Theme.GREEN}[INFO] 原标签与 LLM 建议一致，自动跳过人工标注.{Theme.RESET}")
            DONE_IDS.add(sample_id_from_code("\n".join(code.splitlines())))
            continue  # 跳过人工标注

        # ===========================
        # 否则进入人工标注流程
        # ===========================
        result = manual_annotate(code.splitlines(), sample.get("labels", []), info, suggestion)

        if result is None:
            break

        sample["labels"] = result
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n{Theme.BOLD}{Theme.GREEN}所有改动已保存至: {output_path}{Theme.RESET}")

if __name__ == "__main__":
    main()