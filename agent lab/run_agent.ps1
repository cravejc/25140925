$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$env:PYTHONWARNINGS = "ignore"
$env:ANGR_LOG_LEVEL = "CRITICAL"
$env:Path = "$Root\tools\john\bin;$env:Path"

& "$Root\tools\angr-python\python.exe" .\agent\react_angr_agent.py
