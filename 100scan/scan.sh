#!/bin/bash

# 定义目标目录和结果目录
REPO_DIR="/Users/djoker/Desktop/CTGA/100scan/data/repo"
RESULT_DIR="/Users/djoker/Desktop/CTGA/100scan/data/bandit_results"

# 创建结果目录
mkdir -p "$RESULT_DIR"

# 遍历每个仓库目录
for repo in "$REPO_DIR"/*; do
    if [ -d "$repo" ]; then
        repo_name=$(basename "$repo")
        result_file="$RESULT_DIR/${repo_name}_bandit.csv"

        echo "正在扫描仓库: $repo_name"
        
        # 使用 bandit 扫描仓库并保存结果为 CSV
        bandit -r "$repo" -f csv -o "$result_file"

        echo "扫描完成: $repo_name -> $result_file"
    fi
done

echo "所有仓库扫描完成，结果保存在 $RESULT_DIR"