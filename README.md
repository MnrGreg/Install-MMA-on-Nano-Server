# Install-MMA-on-Nano-Server
Powershell script to install the OMS Microsoft Monitoring Agent onto Nano Servers

This script installs the MMA on the given Nano Server machine. The agent install file MMASetup-AMD64.exe must exist in the current path. Download from https://go.microsoft.com/fwlink/?LinkId=828603 or your OMS workspace. This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server.

## EXAMPLE

  Install-MMA-on-Nano-Server.ps1 MyNanoServerName 1234567 1234567


## NOTES
One can also change the WorkSpace details post install with the following:

  $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
  $mma.AddCloudWorkspace($workspaceId, $workspaceKey)
  $mma.ReloadConfiguration()
  
For implementation using Desired State Configuration view the following:
https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-windows-agents
