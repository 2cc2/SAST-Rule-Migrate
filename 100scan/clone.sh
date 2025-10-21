#!/bin/bash


TARGET_DIR="/Users/djoker/Desktop/CTGA/demo/100scan/data/repo"
CSV_FILE="/Users/djoker/Desktop/CTGA/demo/100scan/data/100.csv"

mkdir -p "$TARGET_DIR"
tail -n +2 "$CSV_FILE" | while IFS=, read -r project_name repo_url; do
    if [ -z "$repo_url" ]; then
        echo "跳过 $project_name，因为没有提供 repo_url"
        continue
    fi

    DEST_DIR="$TARGET_DIR/$project_name"
    if [ -d "$DEST_DIR" ]; then
        echo "跳过 $project_name，因为目录已存在"
        continue
    fi
    echo "clone $project_name -> $repo_url"
    git clone "$repo_url" "$TARGET_DIR/$project_name"
done