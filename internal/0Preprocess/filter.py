import csv

def filter_csv(input_file, output_file, include_keywords, exclude_keywords):
    """
    筛选 CSV 文件内容，保留包含指定关键字的行，同时排除包含非相关关键字的行。

    :param input_file: 输入文件路径
    :param output_file: 输出文件路径
    :param include_keywords: 需要包含的关键字列表
    :param exclude_keywords: 需要排除的关键字列表
    """
    with open(input_file, mode="r", encoding="utf-8") as infile, \
         open(output_file, mode="w", newline="", encoding="utf-8") as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # 遍历每一行，筛选符合条件的内容
        for row in reader:
            if not row:  # 跳过空行
                continue
            line = row[0]  # 假设每行只有一列
            if any(keyword in line for keyword in include_keywords) and not any(keyword in line for keyword in exclude_keywords):
                writer.writerow(row)
def compare_csv(file1, file2):
    """
    比较两个 CSV 文件，找出它们的不同内容。

    :param file1: 第一个 CSV 文件路径
    :param file2: 第二个 CSV 文件路径
    """
    with open(file1, "r", encoding="utf-8") as f1, open(file2, "r", encoding="utf-8") as f2:
        # 读取文件内容到集合中
        set1 = set(line.strip() for line in f1 if line.strip())
        set2 = set(line.strip() for line in f2 if line.strip())

    # 找出差异
    only_in_file1 = set1 - set2
    only_in_file2 = set2 - set1

    # 输出结果
    print("以下内容仅存在于 {}:".format(file1))
    for line in only_in_file1:
        print(line)

    print("\n以下内容仅存在于 {}:".format(file2))
    for line in only_in_file2:
        print(line)


    

    # 比较文件
    
if __name__ == "__main__":
    # 输入文件路径
    input_csv = "codeql.csv"
    # 输出文件路径
    output_csv = "filtered_codeql_java.csv"
    # 包含的关键字
    include = [ "java"]
    # include=[""]
    # 排除的关键字
    exclude = ["images",".github",".git","change-notes","swift", "cpp",  "csharp", "ruby",  "kotlin", "scala", "rust","actions"
]

    # # 执行筛选
    filter_csv(input_csv, output_csv, include, exclude)
    print(f"筛选完成，结果已保存到 {output_csv}")
    # file1 = "filtered_codeql.csv"
    # file2 = "filtered_codeql2.csv"
    # compare_csv(file1, file2)