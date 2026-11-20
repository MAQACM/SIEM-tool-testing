# install_wazuh_agent_windows.ps1 — enroll a Windows VICTIM VM into the VPS Wazuh manager
#
# Run ON the Windows victim VM in an ADMIN PowerShell (not the VPS, not Kali):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\install_wazuh_agent_windows.ps1 -Manager <VPS_PUBLIC_IP> [-AgentName windows-victim]
#
# Installs the Wazuh agent v4.8 and Sysmon (paper §10.1.2 Windows telemetry).
# NOTE: on Apple Silicon the guest is Windows 11 ARM; use the ARM64 Sysmon build.
param(
    [Parameter(Mandatory=$true)][string]$Manager,
    [string]$AgentName = "windows-victim"
)
$ErrorActionPreference = "Stop"

Write-Host "[*] Downloading Wazuh agent 4.8.0..."
$msi = "$env:TEMP\wazuh-agent-4.8.0-1.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi" -OutFile $msi

Write-Host "[*] Installing + registering to manager $Manager as '$AgentName'..."
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=`"$Manager`" WAZUH_AGENT_NAME=`"$AgentName`"" -Wait

Write-Host "[*] Installing Sysmon (Windows telemetry)..."
$sz = "$env:TEMP\Sysmon.zip"; $sd = "$env:TEMP\Sysmon"
# Use Sysmon64a.exe on ARM Windows; Sysmon64.exe on x64 Windows.
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sz
Expand-Archive -Path $sz -DestinationPath $sd -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$sd\sysmonconfig.xml"
$sysmonExe = if (Test-Path "$sd\Sysmon64a.exe") { "$sd\Sysmon64a.exe" } else { "$sd\Sysmon64.exe" }
& $sysmonExe -accepteula -i "$sd\sysmonconfig.xml"

Write-Host "[*] Enabling Sysmon channel in the Wazuh agent config..."
$ossec = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$cfg = Get-Content $ossec -Raw
if ($cfg -notmatch "Microsoft-Windows-Sysmon/Operational") {
    $block = "  <localfile>`n    <location>Microsoft-Windows-Sysmon/Operational</location>`n    <log_format>eventchannel</log_format>`n  </localfile>`n</ossec_config>"
    $cfg = $cfg -replace "</ossec_config>", $block
    Set-Content -Path $ossec -Value $cfg
}

Restart-Service -Name WazuhSvc
Write-Host "[OK] Enrolled. Confirm 'Active' on the Wazuh dashboard > Agents."
