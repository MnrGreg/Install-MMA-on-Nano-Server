# Install-MMA-on-Nano-Server
A Powershell script to install the OMS Microsoft Monitoring Agent onto Nano Servers

This script installs MMA on Nano Server without SCOM or ActiveDirectory dependancies with the intention of attaching to Azure OMS only. Note, the SCOM/MMA agent install files (version 8.0.10709.0) are used for this install. Copy the content from the SCOM2016 ISO ":\NanoAgent\" folder to your current path. This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server. WMF 5.0 is required for Copy-Item to NanoServer.

## EXAMPLE

  Install-MMA-on-Nano-Server.ps1 MyNanoServerName MyOMSWorkSpaceID MyOMSWorkSpaceKey


## NOTES
The SCOM2016 \NanoServer\InstallNanoServerScomAgentOnline.ps1 script was heaviliy modified to cater for this installation. Functionaly may be different from the MMASetup-AMD64 install.

Script can be found at:
https://github.com/MnrGreg/Install-MMA-on-Nano-Server
https://www.powershellgallery.com/packages/Install-MMA-on-Nano-Server/
