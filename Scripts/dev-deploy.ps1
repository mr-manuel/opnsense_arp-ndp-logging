<#
.SYNOPSIS
    Dev-sync deploy for the ArpNdpLogging OPNsense plugin.

.DESCRIPTION
    Copies the working tree's src/ folder directly onto an OPNsense test box
    under /usr/local/ (the same layout the built pkg installs to), then
    reloads the services that need to pick up the change (configd, php-fpm),
    so you can test in-progress changes on a real firewall without cutting a
    release or building a .pkg first.

    This works against a box that never had the plugin pkg-installed too -
    cp -R creates any missing directories under /usr/local/ as needed.

    WARNING: this bypasses pkg's file registry (the files land on disk but
    `pkg info`/`pkg delete` won't know about them). Only run this against a
    disposable test VM, never a production firewall. The real release still
    goes through `make package` and the GitHub Actions build workflow.

    Requires PuTTY's plink.exe and pscp.exe on PATH, and SSH enabled on the
    target (System -> Settings -> Administration -> Secure Shell).

    Runs plink/pscp with -batch so login banners ("Press Return to begin
    session") don't wait for a keypress. -batch also means an unrecognized
    host key gets rejected instead of prompted for - if this is the very
    first connection to that host, connect once with plain plink first (no
    -batch) to accept and cache its key, then rerun this script.

.EXAMPLE
    .\Scripts\dev-deploy.ps1

.EXAMPLE
    .\Scripts\dev-deploy.ps1 -OpnsenseHost 192.168.1.1 -OpnsenseUser root
#>

param(
    [string]$OpnsenseHost,
    [string]$OpnsenseUser = "root"
)

$ErrorActionPreference = "Stop"

foreach ($tool in @("plink", "pscp")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "$tool was not found on PATH. Install PuTTY (provides plink.exe and pscp.exe) and try again."
        exit 1
    }
}

if (-not $OpnsenseHost) {
    $OpnsenseHost = Read-Host "OPNsense IP or hostname"
}
if (-not $OpnsenseUser) {
    $OpnsenseUser = Read-Host "SSH username"
}

$securePassword = Read-Host "SSH password for $OpnsenseUser@$OpnsenseHost" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $repoRoot "src"
$remoteTmp = "/tmp/arpndplogging_dev_sync"

if (-not (Test-Path $srcDir)) {
    Write-Error "src/ directory not found at $srcDir"
    exit 1
}

Write-Host "Preparing remote temp directory ..."
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost "rm -rf $remoteTmp; mkdir -p $remoteTmp"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not prepare $remoteTmp on the remote host."
    exit 1
}

Write-Host "Uploading $srcDir to ${OpnsenseUser}@${OpnsenseHost}:$remoteTmp ..."
& pscp -r -batch -pw $password "$srcDir" "${OpnsenseUser}@${OpnsenseHost}:$remoteTmp"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Upload failed."
    exit 1
}

Write-Host "Installing files ..."
$deployCommand = "cp -Rf $remoteTmp/src/* /usr/local/ && chmod +x /usr/local/etc/rc.d/arpndplogging && rm -rf $remoteTmp"
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost $deployCommand
if ($LASTEXITCODE -ne 0) {
    Write-Error "Remote deploy command failed (exit $LASTEXITCODE) - see output above."
    exit 1
}

Write-Host "Reloading configd (picks up new/changed configd actions) ..."
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost "service configd restart"

Write-Host "Reloading the web GUI (clears PHP's compiled-code cache) ..."
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost "configctl webgui restart"

Write-Host "Restarting the arpndplogging service if it is already enabled ..."
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost "service arpndplogging restart" | Out-Null

Write-Host ""
Write-Host "Deploy complete. Current service status:"
& plink -ssh -batch -l $OpnsenseUser -pw $password $OpnsenseHost "service arpndplogging status"

Write-Host ""
Write-Host "Next: open https://$OpnsenseHost/ui/arpndplogging/general and use the Send"
Write-Host "test mail/webhook buttons (they save and reconfigure automatically), and/or"
Write-Host "trigger a device change on the network to verify."

$password = $null
