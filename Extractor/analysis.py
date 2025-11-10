import os
from collections import defaultdict

def save_sorted_filenames_by_category(directory, output_file):
    """获取指定目录下的所有文件名，按字典序排序并按文件类型分类保存到文件中"""
    if not os.path.exists(directory):
        print(f"目录 {directory} 不存在！")
        return

    # 获取所有文件名并分类
    categorized_files = defaultdict(list)
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.relpath(os.path.join(root, file), directory)
            file_extension = os.path.splitext(file)[1] or "[no extension]"
            categorized_files[file_extension].append(file_path)

    # 按字典序排序每个分类的文件
    for ext in categorized_files:
        categorized_files[ext].sort()

    # 保存到文件
    with open(output_file, "w", encoding="utf-8") as f:
        for ext, files in sorted(categorized_files.items()):
            f.write(f"# {ext}\n")
            f.write("\n".join(files))
            f.write("\n\n")

    print(f"分类后的文件名已保存到 {output_file}")

if __name__ == "__main__":
    directory = "/home/cbb/codeql/docs"
    output_file = "doc_filenames.txt"
    save_sorted_filenames_by_category(directory, output_file)