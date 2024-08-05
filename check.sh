#!/bin/bash

# Function to run commands and check for failures
run_command() {
    local command="$1"
    
    echo -e "\033[34mRunning: $command\033[0m"
    eval "$command"
    
    if [ $? -ne 0 ]; then
        echo -e "\033[31mCheck failed: $command\033[0m"
        exit 1
    fi
}

# Function to count non-empty lines in .rs files
count_lines() {
    local src="$1"
    
    if [ ! -d "$src" ]; then
        echo "Folder '$src' doesn't exist."
        exit 1
    fi
    
    local non_empty_lines=0
    
    find "$src" -type f -name "*.rs" | while read -r file; do
        local lines
        lines=$(grep -cve '^[[:space:]]*$' "$file")
        non_empty_lines=$((non_empty_lines + lines))
    done
    
    echo "$non_empty_lines"
}

run_command "cargo build --lib"
run_command "cargo build --lib --target x86_64-unknown-none"
run_command "cargo test"
run_command "cargo run --example new_struct"
run_command "cargo clippy --all-targets --all-features -- -D warnings --no-deps"
run_command "cargo test --release -- --ignored"
run_command "cargo fmt"

echo -e "\n./src contains $(count_lines 'src') non-empty lines" 
echo -e "\033[32mReady to push!\033[0m"
