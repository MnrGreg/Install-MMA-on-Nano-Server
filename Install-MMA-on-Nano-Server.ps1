
<#PSScriptInfo

.VERSION 1.0.4

.GUID 5da7965b-b1bc-4e4b-80ff-9fd89192cc7f

.AUTHOR Gregory May

.COMPANYNAME 

.COPYRIGHT 

.TAGS Nano MMA/SCOM Microsoft Monitoring Agent

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION 
 This script installs MMA on Nano Server without SCOM/AD dependancies with the intention of attaching only to Azure OMS only.
 This uses the SCOM/MMA from the SCOM2016 ISO. Please copy the ":\NanoAgent\*" contents to your current path.
 This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server.
 The .\NanoServer\InstallNanoServerScomAgentOnline.ps1 script was heaviliy modified to cater for this installation. Functionaly may be different from the MMASetup-AMD64 install.
 Code is also updated at https://github.com/MnrGreg/Install-MMA-on-Nano-Server

.SYNOPSIS 
Remotely installs the Microsoft Monitoring Agent on to Nano Servers.

.EXAMPLE
Install-MMA-on-Nano-Server.ps1 MyNanoServerName MyOMSWorkSpaceID MyOMSWorkSpaceKey

#> 


param (
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$NanoServer, 
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_ID,
[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$OPSINSIGHTS_WS_KEY)

Write-Output "`nAdding $NanoServer to local WSMAN TrustedHosts client list"
Set-Item wsman:localhost\Client\TrustedHosts "$NanoServer" -Concatenate –Force
Write-Output "`nInitiating PSSession to $NanoServer"
$TargetSession = new-PSSession -ComputerName $NanoServer -Credential (Get-Credential)
Write-Output "Copying MOM Agent files to $NanoServer C:\MMA-Nano-Agent"

Copy-Item -Path ".\" -Destination "C:\MMA-Nano-Agent"  -recurse -force -ToSession $TargetSession -Verbose
If ($?) {
    New-PSSession $TargetSession
    Write-Output "`nExecuting remote agent installation..."
    Invoke-command -session $TargetSession -FilePath .\InstallLocalScomAgent.ps1

    Write-Output "`nApplying OMS Workspace keys:  `n Workspace ID: $OPSINSIGHTS_WS_ID  `n Workspace Key: $OPSINSIGHTS_WS_KEY"
    Invoke-Command  -session $TargetSession -ScriptBlock {
        param($ROPSINSIGHTS_WS_ID, $ROPSINSIGHTS_WS_KEY)
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
        $mma.AddCloudWorkspace($ROPSINSIGHTS_WS_ID,$ROPSINSIGHTS_WS_KEY)
        $mma.ReloadConfiguration()
        }   -ArgumentList $OPSINSIGHTS_WS_ID, $OPSINSIGHTS_WS_KEY
    
    Write-Output "Attempting to start HealthService"
    Invoke-Command  -session $TargetSession -ScriptBlock {
        Get-Service -Name HealthService  | Set-Service -Status Running
        }   
    }   
    Else {
        Write-Output "Unable to Copy File. Check Powershell version = WMF5 and MOMAgent is in current path."
        Break
    }