# Richiede Amministratore. Installa il compagno dell'engine `vpcd-stub`
# (adapter v1, solo loopback 127.0.0.1:35963) come Scheduled Task all'avvio
# del sistema. Il protocollo è definito dal progetto (framing len BE32 || cmd,
# comandi 0x10..0x13 in desktop/src-tauri/src/vpcd.rs): nessun demone esterno.
#
# Uso (dalla radice del repo, in PowerShell Amministratore):
#   powershell -ExecutionPolicy Bypass -File scripts/install-vpcd-windows.ps1
$ErrorActionPreference = "Stop"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  throw "cargo non trovato: installa Rust (rustup) prima di rilanciare"
}
Write-Host "[*] cargo build -p nfc-desktop --bin vpcd-stub --release"
cargo build -p nfc-desktop --bin vpcd-stub --release
if ($LASTEXITCODE -ne 0) { throw "build vpcd-stub fallita" }

$Src = Join-Path (Get-Location) "target\release\vpcd-stub.exe"
if (-not (Test-Path $Src)) { throw "vpcd-stub.exe non prodotto in $Src" }

$InstallDir = "$env:ProgramFiles\NFCRemote"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Bin = Join-Path $InstallDir "vpcd-stub.exe"
Copy-Item -Force $Src $Bin

# Console app: va come Scheduled Task di sistema all'avvio, non come servizio
# nativo (per quello servirebbe un wrapper tipo nssm). Firewall: nessuna regola
# inbound esterna — solo loopback, che Windows consente di default.
$Task = "NFC Remote vpcd"
if (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $Task -Confirm:$false
}
$Action    = New-ScheduledTaskAction -Execute $Bin -Argument "--host 127.0.0.1 --port 35963"
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $Task -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName $Task

New-Item -Path "HKLM:\Software\NFCRemote" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\NFCRemote" -Name "VpcdPort" -Value 35963
Write-Host "[OK] vpcd-stub in esecuzione su 127.0.0.1:35963 (task '$Task')"