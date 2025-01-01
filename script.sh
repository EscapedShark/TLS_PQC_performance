#!/bin/bash

# 设置 loop 文件夹路径
LOOP_DIR="./loop6"

# 检查 loop 文件夹是否存在
if [ ! -d "$LOOP_DIR" ]; then
    echo "Error: $LOOP_DIR directory not found"
    exit 1
fi

# 遍历 loop 文件夹中的所有 yml 文件
for yml_file in "$LOOP_DIR"/*.yml; do
    if [ -f "$yml_file" ]; then
        echo "Running benchmark for $yml_file"
        python3 benchmark.py "$yml_file"
        
        # 检查 Python 脚本的退出状态
        if [ $? -ne 0 ]; then
            echo "Error: Benchmark failed for $yml_file"
        else
            echo "Benchmark completed for $yml_file"
        fi
        
        echo "-----------------------------------"
    fi
done

echo "All benchmarks completed"