# Setup dominio locale nfc.local (UNA TANTUM, eseguire come Amministratore per hosts).
# Idempotente: PKI via binario, hosts, fiducia CA CurrentUser (niente admin per trust).
$ErrorActionPreference = "Stop"
$Bin = $env:NFC_BIN
if (-not $Bin) { $Bin = ".\target\release\nfc-desktop.exe" }

Write-Host "== [1/3] PKI locale =="
& $Bin --setup-local-domain

$Profile = Join-Path $env:APPDATA "NFCRemote"
$CA = Join-Path $Profile "ca\nfc-local-root.pem"

Write-Host "== [2/3] hosts nfc.local -> 127.0.0.1 =="
$Hosts = "C:\Windows\System32\drivers\etc\hosts"
$Needed = "127.0.0.1 nfc.local api.nfc.local app.nfc.local pair.nfc.local"
if (-not (Select-String -Path $Hosts -Pattern "nfc\.local" -Quiet)) {
  Add-Content -Path $Hosts -Value $Needed
  Write-Host "hosts aggiornato"
} else { Write-Host "hosts già presente" }

Write-Host "== [3/3] fiducia CA (CurrentUser Root) =="
certutil -user -addstore Root $CA | Out-Null
Write-Host "CA fidata. Firefox: about:config security.enterprise_roots.enabled=true oppure importa $CA."

Write-Host "== verifica =="
Invoke-RestMethod -Uri "https://nfc.local:8443/v1/status"
