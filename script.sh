#!/bin/bash


#set loop folder path
LOOP_DIR="./loop"

# check if loop folder exists
if [ ! -d "$LOOP_DIR" ]; then
    echo "Error: $LOOP_DIR directory not found"
    exit 1
fi

# check if python3 is installed
for yml_file in "$LOOP_DIR"/*.yml; do
    if [ -f "$yml_file" ]; then
        echo "Running benchmark for $yml_file"
        python3 benchmark.py "$yml_file"
        
        #check the exit status of the python script
        if [ $? -ne 0 ]; then
            echo "Error: Benchmark failed for $yml_file"
        else
            echo "Benchmark completed for $yml_file"
        fi
        
        echo "-----------------------------------"
    fi
done

echo "All benchmarks completed"