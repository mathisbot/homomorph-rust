function Run-Command {
    param (
        [string]$Command
    )
    
    Write-Host -NoNewline "Running: " -ForegroundColor Blue
    Write-Host $Command
    Invoke-Expression $Command > $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Check failed: $Command" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

function Count-Lines {
    param (
        [string]$src
    )

    # This shouldn't happen
    if (-Not (Test-Path -Path $src)) {
        Write-Host "Folder '$src' doesn't exist."
        exit
    }
    $nonEmptyLines = 0

    $files = Get-ChildItem -Path $src -File -Recurse -Include *.rs

    foreach ($f in $files) {
        $lines = Get-Content -Path $f.FullName
        
        $nonEmptyLines += ($lines | Where-Object { $_.Trim().Length -gt 0 }).Count
    }

    return $nonEmptyLines
}

Run-Command "cargo build --lib --all-features"
Run-Command "cargo build --lib --target x86_64-unknown-none --all-features"
Run-Command "cargo test --all-features"
Run-Command "cargo run --example simple_struct --all-features"
Run-Command "cargo run --example unbalanced_struct --all-features"
Run-Command "cargo clippy --all-targets --all-features -- -D warnings --no-deps"
Run-Command "cargo test --release --all-features -- --ignored"
Run-Command "cargo fmt"
# Optional
# Run-Command "cargo tarpaulin --lib --all-features --locked --out Html"

Write-Host "`n./src contains $(Count-Lines "src") non-empty lines" -ForegroundColor blue
Write-Host "Ready to push!" -ForegroundColor Green
