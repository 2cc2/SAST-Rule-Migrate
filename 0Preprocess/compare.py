import json

# 假设从 JSON 文件中加载两个列表
with open("/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/java_missed_modules.json", "r", encoding="utf-8") as f1, open("/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/python_missed_modules.json", "r", encoding="utf-8") as f2:
    list1 = json.load(f1)
    list2 = json.load(f2)

# 转成集合
set1 = set(list1)
set2 = set(list2)

# 相同元素
common = set1 & set2

# 仅在 list1
only_in_list1 = set1 - set2

# 仅在 list2
only_in_list2 = set2 - set1

print(f"相同元素 ({len(common)} 个):\n{common}\n")
print(f"仅在 list1 ({len(only_in_list1)} 个):\n{only_in_list1}\n")
print(f"仅在 list2 ({len(only_in_list2)} 个):\n{only_in_list2}\n")