$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$env:JAVA_HOME = Join-Path $Root "tools\jdk-21"
$env:Path = "$env:JAVA_HOME\bin;$Root\tools\r2\bin;$env:Path"
$env:R2_BIN = Join-Path $Root "tools\r2\bin\radare2.exe"
$env:RABIN2_BIN = Join-Path $Root "tools\r2\bin\rabin2.exe"
$env:GHIDRA_HEADLESS = Join-Path $Root "tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat"

python .\agent\react_static_agent.py
