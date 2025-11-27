import csv
import pathlib


def contains_excluded_part(filepath, exclude_keywords):
    """
    判断路径中是否包含排除关键词（按路径段匹配，而不是 substring 匹配）
    """
    parts = pathlib.Path(filepath).parts
    # 只按路径段匹配，例如路径段为 ("codeql", "java", "ql", ...)
    return any(part in exclude_keywords for part in parts)


def filter_csv(input_file, output_file, include_keywords, exclude_keywords, file_extensions=None):
    """
    筛选 CSV 文件，保留包含 include_keywords 的行，
    排除路径段中包含 exclude_keywords 的行，
    并限制扩展名为 file_extensions。
    """
    with open(input_file, mode="r", encoding="utf-8") as infile, \
         open(output_file, mode="w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # 写表头
        header = next(reader, None)
        if header:
            writer.writerow(header)

        for row in reader:
            if not row:
                continue

            filepath = row[0]

            # 1) 扩展名过滤
            if file_extensions and not any(filepath.endswith(ext) for ext in file_extensions):
                continue

            # 2) 必须包含 include（substring 匹配）
            if not any(keyword in filepath for keyword in include_keywords):
                continue

            # 3) 排除 exclude（路径段匹配）
            if contains_excluded_part(filepath, exclude_keywords):
                continue

            # 通过所有过滤，写入 CSV
            writer.writerow(row)


def compare_csv(file1, file2):
    with open(file1, "r", encoding="utf-8") as f1, open(file2, "r", encoding="utf-8") as f2:
        set1 = set(line.strip() for line in f1 if line.strip())
        set2 = set(line.strip() for line in f2 if line.strip())

    only_in_file1 = set1 - set2
    only_in_file2 = set2 - set1

    if only_in_file1:
        print(f"以下内容仅存在于 {file1}:")
        print("\n".join(only_in_file1))
    else:
        print(f"{file1} 中没有独有内容。")

    if only_in_file2:
        print(f"以下内容仅存在于 {file2}:")
        print("\n".join(only_in_file2))
    else:
        print(f"{file2} 中没有独有内容。")


if __name__ == "__main__":
    languages = {
        "python": {
            "include": ["python"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions", "php",
                        "javascript", "java", "go"],
            "extensions": [".ql", ".qll"]
        },
        "java": {
            "include": ["java"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions", "php",
                        "javascript", "python", "go"],
            "extensions": [".ql", ".qll"]
        },
        "go": {
            "include": ["go"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions", "php",
                        "javascript", "java", "python"],
            "extensions": [".ql", ".qll"]
        },
        "javascript": {
            "include": ["javascript"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions", "php",
                        "java", "python", "go"],
            "extensions": [".ql", ".qll"]
        },
        "shared": {
            "include": ["shared"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions", "php",
                        "java", "python", "go"],
            "extensions": [".ql", ".qll"]
        },
        "qlpack": {
            "include": ["qlpack"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions"],
            "extensions": [".yml"]
        },
        "md": {
            "include": ["doc"],
            "exclude": ["images", "test", ".github", ".git", "change-notes", "swift", "cpp",
                        "csharp", "ruby", "kotlin", "scala", "rust", "actions"],
            "extensions": [".md"]
        }
    }

    input_csv = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/basic/study/input/codeql.csv"

    for language, conditions in languages.items():
        output_csv = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/filelist/{language}.csv"

        filter_csv(
            input_csv,
            output_csv,
            include_keywords=conditions["include"],
            exclude_keywords=conditions["exclude"],
            file_extensions=conditions.get("extensions")
        )

        print(f"筛选完成，{language} 的结果已保存到 {output_csv}")