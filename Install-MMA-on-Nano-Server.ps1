<#
    .SYNOPSIS 
     Remotely installs the Microsoft Monitoring Agent on to Nano Servers. 

    .EXAMPLE
     Install-MMA-on-Nano-Server.ps1 MyNanoServerName 1234567 1234567

    .DESCRIPTION
     This script installs the MMA on the given Nano Server machine. The agent install file MMASetup-AMD64.exe must exist in the current path. Download from https://go.microsoft.com/fwlink/?LinkId=828603 or your OMS workspace.
     This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server.
#>

param (
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$NanoServer, 
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_ID,
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_KEY)

Set-Item wsman:localhost\Client\TrustedHosts "$NanoServer" -Concatenate –Force
$TargetSession = new-PSSession -ComputerName $NanoServer -Credential (Get-Credential)
Copy-Item -Path ".\MMASetup-AMD64.exe" -Destination "C:\" -force -ToSession $TargetSession
New-PSSession $TargetSession
Invoke-command -session $TargetSession -scriptblock {
    C:\MMASetup-AMD64.exe /Q:A /R:N /C:"setup.exe /qn ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_ID=' + $OPSINSIGHTS_WS_ID + ' OPINSIGHTS_WORKSPACE_KEY=' + $OPSINSIGHTS_WS_KEY + ' AcceptEndUserLicenseAgreement=1" | Write-Output
    Get-service healthservice
    Remove-Item C:\MMASetup-AMD64.exe -Force }