import json
import os
import copy

class Theme:
    RED = '\033[91m'      # Bad
    GREEN = '\033[92m'    # Good
    YELLOW = '\033[93m'   # 行号
    BLUE = '\033[94m'     # 进度和提示
    RESET = '\033[0m'
    BOLD = '\033[1m'

def manual_annotate(lines, existing_labels, info_header):
    """
    交互式标注逻辑
    """
    new_labels = copy.deepcopy(existing_labels)
    
    while True:
        # 排序以保证显示美观
        new_labels.sort(key=lambda x: x["StartLine"])
        
        # 清屏并显示头部信息
        print("\033[H\033[J", end="") 
        print(f"{Theme.BOLD}{Theme.BLUE}=== 标注助手 === {info_header}{Theme.RESET}")
        print("-" * 60)

        # 打印带有颜色标注的代码
        for i, line in enumerate(lines, 1):
            color = ""
            tag = ""
            for lb in new_labels:
                if lb["StartLine"] <= i <= lb["EndLine"]:
                    color = Theme.RED if lb["label"] == "bad" else Theme.GREEN
                    tag = f"[{lb['label'].upper()}]"
                    break
            print(f"{Theme.YELLOW}{i:3}{Theme.RESET} | {color}{tag:10} {line}{Theme.RESET}")

        print(f"\n{Theme.BLUE}操作指令:{Theme.RESET}")
        print("  - 标注: 'bad 5 10' 或 'good 15 20' (自动覆盖重叠部分)")
        print("  - 'clear': 清空当前标注 | 's': 保存并下一个 | 'q': 退出程序")
        
        cmd = input(f"\n{Theme.BOLD}>> {Theme.RESET}").strip().lower()

        if cmd == 's':
            return new_labels
        elif cmd == 'q':
            if input("确定退出吗？当前样本的修改将丢失 (y/n): ") == 'y':
                return None
        elif cmd == 'clear':
            new_labels = []
        else:
            try:
                parts = cmd.split()
                if len(parts) == 3:
                    lbl, start, end = parts[0], int(parts[1]), int(parts[2])
                    if lbl in ['good', 'bad'] and start <= end:
                        # 核心功能：自动覆盖旧的重叠区域
                        new_labels = [lb for lb in new_labels if not (lb["StartLine"] <= end and lb["EndLine"] >= start)]
                        new_labels.append({"label": lbl, "StartLine": start, "EndLine": end})
                else:
                    print("格式错误！按回车继续...")
                    input()
            except Exception as e:
                print(f"输入无效: {e}。按回车继续...")
                input()

def main():
    input_path = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example_labeled.json"
    output_path = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example_manual_fixed.json"

    if not os.path.exists(input_path):
        print(f"找不到输入文件: {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 1. 扁平化所有样本，方便排序
    sample_queue = []
    # 假设 JSON 结构: java -> rule_name -> examples -> samples
    if "java" in data:
        for rule_name, rule_content in data["java"].items():
            if isinstance(rule_content, dict) and "examples" in rule_content:
                for example in rule_content["examples"]:
                    for sample in example.get("samples", []):
                        sample_queue.append({
                            "rule": rule_name,
                            "data_ref": sample, # 保持引用，直接修改此对象
                            "is_unlabeled": len(sample.get("labels", [])) == 0
                        })

    # 2. 排序：未标注的 (is_unlabeled=True) 优先
    # True 在排序中等效于 1，所以我们降序排（True在前）
    sample_queue.sort(key=lambda x: x["is_unlabeled"], reverse=True)

    total = len(sample_queue)
    unlabeled_count = sum(1 for s in sample_queue if s["is_unlabeled"])
    print(f"加载成功：总计 {total} 个样本，其中 {unlabeled_count} 个待标注。")
    input("按回车开始...")

    # 3. 循环标注
    for idx, item in enumerate(sample_queue, 1):
        sample = item["data_ref"]
        status = "[待标注]" if item["is_unlabeled"] else "[已有标注]"
        info = f"进度: {idx}/{total} | 规则: {item['rule']} | 状态: {status}"
        
        lines = sample.get("code", "").splitlines()
        
        # 进入交互界面
        result = manual_annotate(lines, sample.get("labels", []), info)
        
        if result is None: # 用户输入 'q'
            print("正在退出并保存已完成的部分...")
            break
            
        # 更新数据并保存
        sample["labels"] = result
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"样本 {idx} 已保存。")

    print(f"\n{Theme.GREEN}所有操作已完成。结果保存在: {output_path}{Theme.RESET}")

if __name__ == "__main__":
    main()