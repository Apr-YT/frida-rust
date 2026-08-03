# 部署 frida-server 到连接的 Android 设备
# 用法: powershell -ExecutionPolicy Bypass -File scripts\deploy-frida-server.ps1 [-Serial <序列号>] [-Port 27042]
param(
    [string]$Serial = "",
    [int]$Port = 27042
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# 1. 选择设备
if ($Serial -eq "") {
    $line = adb devices | Select-String -Pattern "^\S+\s+device($|\s)" | Select-Object -First 1
    if (-not $line) { Write-Host "[ERR] 未找到在线 adb 设备"; exit 1 }
    $Serial = (($line.ToString() -split "\s+")[0]).Trim()
}
Write-Host "[1/4] 目标设备: $Serial"

# 2. WSL 交叉编译
Write-Host "[2/4] WSL 交叉编译 frida-server (aarch64-linux-android, release)..."
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/d/project/trae/frida-rust-mcp && cargo build -p frida-server --target aarch64-linux-android --release 2>&1 | tail -n 2"
if ($LASTEXITCODE -ne 0) { Write-Host "[ERR] 编译失败"; exit 1 }

# 3. 推送并启动守护进程
$bin = Join-Path $Repo "target\aarch64-linux-android\release\frida-server"
Write-Host "[3/4] 推送并启动守护进程 (root, setenforce 0)..."
adb -s $Serial push $bin /data/local/tmp/frida-server | Out-Null
# 注意: 用 pkill -x 精确匹配进程名, 避免 pkill -f 误杀执行本命令的 shell
adb -s $Serial shell "su -c 'pkill -x frida-server 2>/dev/null; setenforce 0; chmod 755 /data/local/tmp/frida-server; setsid /data/local/tmp/frida-server </dev/null >/data/local/tmp/frida-server.log 2>&1 &'" 2>&1 | Out-Null
Start-Sleep -Seconds 2

# 4. adb forward + 验证
Write-Host "[4/4] 设置 adb forward tcp:$Port -> localabstract:frida"
adb -s $Serial forward --remove tcp:$Port 2>$null | Out-Null
adb -s $Serial forward tcp:$Port localabstract:frida | Out-Null

$ps = adb -s $Serial shell "ps -A | grep frida-server"
$log = adb -s $Serial shell "cat /data/local/tmp/frida-server.log 2>/dev/null"
Write-Host "进程: $ps"
Write-Host "日志: $log"
if ($ps -match "frida-server") {
    Write-Host "部署完成。主机侧连接: tcp://127.0.0.1:$Port"
} else {
    Write-Host "[WARN] 未检测到 frida-server 进程, 请检查日志"
}
