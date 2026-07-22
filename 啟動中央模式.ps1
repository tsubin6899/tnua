param(
  [string]$HostAddress = '127.0.0.1',
  [int]$Port = 4178
)

$ErrorActionPreference = 'Stop'
$siteDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$bundledNode = 'C:\Users\TNUA-BIN\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'

if ($nodeCommand) {
  $nodeExecutable = $nodeCommand.Source
} elseif (Test-Path -LiteralPath $bundledNode) {
  $nodeExecutable = $bundledNode
} else {
  throw '找不到 Node.js。請先安裝 Node.js 20 以上版本，再重新執行。'
}

$env:TNUA_HOST = $HostAddress
$env:TNUA_PORT = [string]$Port

Write-Host "招生統計中央模式：http://${HostAddress}:${Port}"
Write-Host '按 Ctrl+C 可停止服務。'
& $nodeExecutable (Join-Path $siteDirectory 'central-server.mjs')

