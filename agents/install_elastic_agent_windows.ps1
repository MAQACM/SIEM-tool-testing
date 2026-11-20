# install_elastic_agent_windows.ps1 — enroll a Windows VICTIM VM into VPS Fleet (Elastic)
#
# Run ON the Windows victim VM in an ADMIN PowerShell AFTER 05_setup_elastic.sh and after
# copying the enrollment token from Kibana > Fleet > Agents > Add agent:
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\install_elastic_agent_windows.ps1 -Vps <VPS_PUBLIC_IP> -Token <ENROLLMENT_TOKEN>
#
# On Apple Silicon the guest is Windows 11 ARM. Elastic ships a Windows x86_64 agent that
# runs under emulation; Elastic Defend endpoint features may be limited on ARM — verify
# agent health after enrollment and note any gaps as a methodology limitation.
param(
    [Parameter(Mandatory=$true)][string]$Vps,
    [Parameter(Mandatory=$true)][string]$Token
)
$ErrorActionPreference = "Stop"
$ver = "8.11.0"
$pkg = "elastic-agent-$ver-windows-x86_64"

Write-Host "[*] Downloading Elastic Agent $ver..."
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/$pkg.zip" -OutFile "$env:TEMP\$pkg.zip"
Expand-Archive -Path "$env:TEMP\$pkg.zip" -DestinationPath "$env:TEMP" -Force
Set-Location "$env:TEMP\$pkg"

Write-Host "[*] Installing Sysmon for host telemetry..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\Sysmon\cfg.xml"
$sysmon = if (Test-Path "$env:TEMP\Sysmon\Sysmon64a.exe") { "$env:TEMP\Sysmon\Sysmon64a.exe" } else { "$env:TEMP\Sysmon\Sysmon64.exe" }
& $sysmon -accepteula -i "$env:TEMP\Sysmon\cfg.xml"

Write-Host "[*] Enrolling to Fleet at http://${Vps}:8220 ..."
.\elastic-agent.exe install --non-interactive --url="http://${Vps}:8220" --enrollment-token="$Token" --insecure

Write-Host "[*] Agent status:"
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
Write-Host "[OK] Enrolled. In Kibana attach 'Windows', 'Sysmon' and 'Elastic Defend' integrations"
Write-Host "     to this agent's policy, then enable prebuilt detection rules."
