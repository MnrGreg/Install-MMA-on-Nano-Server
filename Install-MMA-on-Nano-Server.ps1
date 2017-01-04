<#
    .SYNOPSIS 
     Remotely installs the Microsoft Monitoring Agent on to Nano Servers. 

    .EXAMPLE
     Install-MMA-on-Nano-Server.ps1 MyNanoServerName 1234567 1234567

    .DESCRIPTION
     This script installs the MMA on the specified Nano Server machine. The agent install file MMASetup-AMD64.exe must exist in the current path. Download from https://go.microsoft.com/fwlink/?LinkId=828603 or your OMS workspace.
     This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server.
#>

param (
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$NanoServer, 
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_ID,
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_KEY)

Write-Output "`nAdding $NanoServer to local WSMAN TrustedHosts client list"
Set-Item wsman:localhost\Client\TrustedHosts "$NanoServer" -Concatenate –Force
Write-Output "`nInitiating PSSession to $NanoServer"
$TargetSession = new-PSSession -ComputerName $NanoServer -Credential (Get-Credential)
Write-Output "Copying MMASetup-AMD64.exe file to $NanoServer C:\"
Copy-Item -Path ".\MMASetup-AMD64.exe" -Destination "C:\" -force -ToSession $TargetSession -Verbose
If ($?) {
    New-PSSession $TargetSession
    Write-Output "`nExecuting remote installation with:  `n Workspace ID: $OPSINSIGHTS_WS_ID  `n Workspace Key: $OPSINSIGHTS_WS_KEY"
    $installcmd = "C:\MMASetup-AMD64.exe"
    $installargs = "/Q:A /R:N /C:""setup.exe /qn ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_ID=$OPSINSIGHTS_WS_ID OPINSIGHTS_WORKSPACE_KEY=$OPSINSIGHTS_WS_KEY AcceptEndUserLicenseAgreement=1"""
    Invoke-command -session $TargetSession -scriptblock {
        param($Rinstallcmd, $Rinstallargs)
        Write-Output "`n$Rinstallcmd $Rinstallargs"
        start-process $Rinstallcmd -ArgumentList $Rinstallargs -Wait
        Write-Output "`nWaiting 20 seconds for HealthService to bootstrap and start"
        Start-Sleep -s 20
        Get-Service healthservice
        Remove-Item C:\MMASetup-AMD64.exe -Force } -ArgumentList $installcmd, $installargs
}
Else {
    Write-Output "Unable to Copy File. Check Powershell version = WMF5"
    Break
}