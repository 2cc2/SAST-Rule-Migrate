import json
import os
import time
import hashlib
from flask import Flask, render_template, request, jsonify
from openai import OpenAI

app = Flask(__name__)

# =========================================================
# 1. 配置与初始化
# =========================================================
client = OpenAI(
    api_key="sk-4a14b8f4281a4418856120d1515bfde0",
    base_url="https://api.deepseek.com"
)

CHECKPOINT_FILE = "checkpoint.json"
INPUT_PATH = "codeql_example_labeled.json"
OUTPUT_PATH = "codeql_example_manual_fixed.json"

DONE_IDS = set()
GLOBAL_DATA = None
SAMPLE_QUEUE = []
CURRENT_INDEX = 0

def analyze_logic(rule_name, code_lines):
    """调用 DeepSeek 进行精确标注分析"""
    numbered_code = "\n".join([f"{i+1:3} | {line}" for i, line in enumerate(code_lines)])
    prompt=f"""
    你是一个精确的代码安全标注助手（DeepSeek），任务是分析 Java 代码样例并进行行级标注。

要求:
1.识别符合规则 "{rule_name}" 的 Bad (漏洞/不规范) 和 Good (修复/规范) 区间。
2. 判定违反规则的区间为 "bad"， 和漏洞代码很相似但没有问题容易误报的代码标为good"。
3. 给每一行自动编号从 1 开始。
4.标注请尽量精确完整，可以没有good或者没有bad。
5. 仅输出 JSON，严格遵守格式：
{{
    "reasoning": "简短描述分析过程",
    "commands": ["bad 起始行 结束行", "good 起始行 结束行","bad 起始行 结束行","good 起始行 结束行",....]
}}
6. 不要输出任何多余文字或解释。

Java 代码如下:
{numbered_code}

请根据上述要求，返回 JSON。
"""
    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "system", "content": "你是一个精确的代码漏洞标注专家。"},
                      {"role": "user", "content": prompt}],
            response_format={'type': 'json_object'}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"reasoning": f"AI 出错: {e}", "commands": []}

def calculate_diff(labels_human, commands_ai):
    """计算差异值：返回最大单行偏移量"""
    labels_ai = []
    for cmd in commands_ai:
        p = cmd.split(' ')
        if len(p) == 3:
            labels_ai.append({"label": p[0], "StartLine": int(p[1]), "EndLine": int(p[2])})
    
    # 提取所有 bad 区间进行比对
    a = sorted([l for l in labels_human if l['label'] == 'bad'], key=lambda x: x['StartLine'])
    b = sorted([l for l in labels_ai if l['label'] == 'bad'], key=lambda x: x['StartLine'])
    
    if not a or not b or len(a) != len(b):
        return 999 # 结构不一致，强制人工介入
    
    max_diff = 0
    for i in range(len(a)):
        d_start = abs(a[i]['StartLine'] - b[i]['StartLine'])
        d_end = abs(a[i]['EndLine'] - b[i]['EndLine'])
        max_diff = max(max_diff, d_start, d_end)
    return max_diff

def init_data():
    global GLOBAL_DATA, SAMPLE_QUEUE, DONE_IDS
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f: 
                DONE_IDS = set(json.load(f).get("done_ids", []))
        except: pass

    target_path = OUTPUT_PATH if os.path.exists(OUTPUT_PATH) else INPUT_PATH
    if not os.path.exists(target_path): return False
    with open(target_path, 'r', encoding='utf-8') as f: 
        GLOBAL_DATA = json.load(f)
    
    SAMPLE_QUEUE = []
    if "java" in GLOBAL_DATA:
        for r_name, r_content in GLOBAL_DATA["java"].items():
            if "examples" in r_content:
                for ex in r_content["examples"]:
                    for smp in ex.get("samples", []):
                        sid = hashlib.sha256(smp.get("code","").encode()).hexdigest()
                        SAMPLE_QUEUE.append({"rule": r_name, "sample_ref": smp, "id": sid})
    return True

def get_response_data(index):
    item = SAMPLE_QUEUE[index]
    return {
        "status": "success", "index": index + 1, "total": len(SAMPLE_QUEUE),
        "rule": item['rule'], "code": item['sample_ref'].get("code", "").splitlines(),
        "existing_labels": item['sample_ref'].get("labels", []),
        "history": item['sample_ref'].get("history", [])
    }

# =========================================================
# 2. 路由接口
# =========================================================
@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/load', methods=['GET'])
def load_sample():
    global CURRENT_INDEX
    direction = request.args.get('dir', 'init')
    if direction == 'next' and CURRENT_INDEX < len(SAMPLE_QUEUE)-1: CURRENT_INDEX += 1
    elif direction == 'prev' and CURRENT_INDEX > 0: CURRENT_INDEX -= 1
    return jsonify(get_response_data(CURRENT_INDEX))

@app.route('/api/last_pos', methods=['GET'])
def last_pos():
    global CURRENT_INDEX
    last_idx = 0
    for i, item in enumerate(SAMPLE_QUEUE):
        if item['id'] in DONE_IDS: last_idx = i
    CURRENT_INDEX = last_idx + 1 
    return jsonify(get_response_data(CURRENT_INDEX))

@app.route('/api/save', methods=['POST'])
def save():
    data = request.json
    item = SAMPLE_QUEUE[CURRENT_INDEX]
    item['sample_ref']['labels'] = data.get('labels', [])
    item['sample_ref']['history'] = data.get('history', [])
    DONE_IDS.add(item['id'])
    with open(CHECKPOINT_FILE, "w") as f: json.dump({"done_ids": list(DONE_IDS)}, f)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f: 
        json.dump(GLOBAL_DATA, f, indent=2, ensure_ascii=False)
    return jsonify({"status": "success"})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    return jsonify(analyze_logic(data['rule'], data['code']))

@app.route('/api/auto_batch_step', methods=['POST'])
def auto_batch_step():
    global CURRENT_INDEX
    if CURRENT_INDEX >= len(SAMPLE_QUEUE): return jsonify({"status": "finished"})
    
    item = SAMPLE_QUEUE[CURRENT_INDEX]
    code_lines = item['sample_ref'].get("code", "").splitlines()
    ai_res = analyze_logic(item['rule'], code_lines)
    
    human_labels = item['sample_ref'].get("labels", [])
    diff = calculate_diff(human_labels, ai_res.get('commands', []))
    
    if diff < 5:
        # 差异极小，自动保存并跳转
        ai_labels = []
        for cmd in ai_res.get('commands', []):
            p = cmd.split(' ')
            if len(p)==3: ai_labels.append({"label": p[0], "StartLine": int(p[1]), "EndLine": int(p[2])})
        
        item['sample_ref']['labels'] = ai_labels
        item['sample_ref']['history'] = [{"name": f"Auto-Approved (Diff:{diff})", "data": ai_labels,"reasoning": ai_res.get('reasoning', ''), # 新增：保存 AI 的分析理由
        "ai_commands": ai_res.get('commands', []),  "time": time.strftime("%H:%M:%S")}]
        DONE_IDS.add(item['id'])
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f: 
            json.dump(GLOBAL_DATA, f, indent=2, ensure_ascii=False)
        
        CURRENT_INDEX += 1
        return jsonify({"status": "auto_saved", "diff": diff, "next_data": get_response_data(CURRENT_INDEX)})
    else:
        # 差异大，暂停
        return jsonify({"status": "require_manual", "diff": diff, "ai_suggestion": ai_res})

if __name__ == '__main__':
    init_data()
    app.run(debug=True, port=5002)