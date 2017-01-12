
<#PSScriptInfo

.VERSION 1.0.6

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
This script installs MMA on Nano Server without SCOM or ActiveDirectory dependancies with the intention of attaching to Azure OMS only. Note, the SCOM/MMA agent install files (version 8.0.10709.0) are used for this install. Copy the content from the SCOM2016 ISO ":\NanoAgent\" folder to your current path. This script has to be run with administrative privileges. The user account which is used to connect to the Nano Server must also have administrative rights on the Nano Server. WMF 5.0 is required for Copy-Item to NanoServer.
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
    Invoke-command -session $TargetSession -ScriptBlock {
        $BinaryFolder = "C:\MMA-Nano-Agent"
        $ERROR = 1
        $INFORMATION = 2
        $installLogFileName = $env:TEMP + "\InstallLog.txt"
        $installStateFileName = $env:TEMP + "\InstallState.txt"

        #State variables. Basically there are going to be 6 states during uninstallation:
        #1. Adding a rule to firewall
        #2. Agent not installed previously
        #3. Registry changes done for MG
        #4. Folders created in Nano server
        #5. Registry changes for Nano Agent in Nano server
        #6. Performance counters installation for MomConnector and HealthService
        $firewallOpened = 1
        $agentNotPreviouslyInstalled = 1
        $managementGroupRegistryDone = 1
        $foldersCreated = 0
        $registryChangesDone = 0
        $countersInstalled = 0
        $cabExpanded = 0


        # Basic strings that would be stored in the uninstall state file in case of failure so that the uninstallation
        # can resume from where it left
        $firewallOpenedSegmentName = "FirewallRuleAdded"
        $agentNotPreviouslyInstalledSegmentName = "AgentNotPreviouslyInstalled"
        $managementGroupRegistryDoneSegmentName = "MGRegistryChangesDone"
        $foldersCreatedSegmentName = "FoldersCreated"
        $registryChangesDoneSegmentName = "RegistryChangesDone"
        $countersInstalledSegmentName = "CountersInstalled"
        $cabExpandedSegmentName = "UpdateCabExpanded"

        # Logging the progress of the install
        $installLog = New-Object System.Collections.ArrayList($null)
        #endregion

        #region Helper Methods

        #region Logging helper methods
        # Saves the state of the installation so that we resume from here in case of retry
        function StoreInstallationState
        {
            $stateContent = New-Object System.Collections.ArrayList($null)
            [void]$stateContent.Add("Please do not delete this file. This file is used by the installer to know about the state of the previous installation. This file would be removed automatically once install is successfull.")
            if($script:cabExpanded -eq 1)
            {
                [void]$stateContent.Add($($script:cabExpandedSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:cabExpandedSegmentName + ":0"))
            }
            if($script:firewallOpened -eq 1)
            {
                [void]$stateContent.Add($($script:firewallOpenedSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:firewallOpenedSegmentName + ":0"))
            }
            if($script:agentNotPreviouslyInstalled -eq 1)
            {
                [void]$stateContent.Add($($script:agentNotPreviouslyInstalledSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:agentNotPreviouslyInstalledSegmentName + ":0"))
            }
            if($script:managementGroupRegistryDone -eq 1)
            {
                [void]$stateContent.Add($($script:managementGroupRegistryDoneSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:managementGroupRegistryDoneSegmentName + ":0"))
            }
            if($script:foldersCreated -eq 1)
            {
                [void]$stateContent.Add($($script:foldersCreatedSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:foldersCreatedSegmentName + ":0"))
            }
            if($script:registryChangesDone -eq 1)
            {
                [void]$stateContent.Add($($script:registryChangesDoneSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:registryChangesDoneSegmentName + ":0"))
            }
            if($script:countersInstalled -eq 1)
            {
                [void]$stateContent.Add($($script:countersInstalledSegmentName + ":1"))
            }
            else
            {
                [void]$stateContent.Add($($script:countersInstalledSegmentName + ":0"))
            }
            $stateContent | out-file -filepath $script:installStateFileName -Force -ErrorAction SilentlyContinue
        }

        # Sets the variable value as read from the current file line
        function SetStateVariable($segment)
        {
            $segmentName = $segment.Split(':')[0]
            $segmentValue = $segment.Split(':')[1]

            if($segmentName -eq $script:cabExpandedSegmentName)
            {
                $script:cabExpanded = $segmentValue
                return
            }
            if($segmentName -eq $script:firewallOpenedSegmentName)
            {
                $script:firewallOpened = $segmentValue
                return
            }
            if($segmentName -eq $script:agentNotPreviouslyInstalledSegmentName)
            {
                $script:agentNotPreviouslyInstalled = $segmentValue
                return 
            }
            if($segmentName -eq $script:managementGroupRegistryDoneSegmentName)
            {
                $script:managementGroupRegistryDone = $segmentValue
                return
            }
            if($segmentName -eq $script:foldersCreatedSegmentName)
            {
                $script:foldersCreated = $segmentValue
                return
            }
            if($segmentName -eq $script:registryChangesDoneSegmentName)
            {
                $script:registryChangesDone = $segmentValue
                return
            }
            if($segmentName -eq $script:countersInstalledSegmentName)
            {
                $script:countersInstalled = $segmentValue
                return
            }
        }

        # Gets the state the installation was left in previously
        function GetPreviousInstallationState()
        {
            $installStateFileContents = (Get-Content $script:installStateFileName)
            for($i = 0; $i -lt $installStateFileContents.Length; $i++)
            {
                $segment = [string]$installStateFileContents[$i]
                SetStateVariable $segment
            }
        }

        # Simple method used to log the progress of the installation
        function LogMessage([string]$message, [int]$logLevel)
        {
            $levelText = ""
            if($logLevel -eq $ERROR)
            {
                $levelText = "[ERROR]"
                Write-Error "There were errors during installation. Please refer to the $script:installLogFileName for more details."
            }
            else
            {
                $levelText = "[INFO]"
            }
            Write-Host $message
            [void]$script:installLog.Add((Get-Date).ToString() + ":" + $levelText + ":" + $message)
            if($logLevel -eq $ERROR)
            {
                # There was an error. Write it down and quit as there is no point in continuing
                $script:installLog | out-file -filepath $script:installLogFileName -Force -ErrorAction SilentlyContinue

                # This method is used so that we know where to resume the installation from the next time
                StoreInstallationState
            }
        }

        #endregion

        #region Agent helper methods

        # Checks to see if the installation is a retry
        function IsInstallRetried()
        {
            # If it is a retry
            if ((Test-Path $script:installStateFileName) -eq $true)
            {
                return $true
            }
            return $false
        }

        # Returns the version of the agent to be installed
        function GetAgentVersion()
        {
            $versionDLLName = "OMVersion.dll"
            $binsFolderExpanded = $RTMCabExpandedFolder
            if($isUpdateCabPresent -eq $true)
            {
                $binsFolderExpanded = $UpdateCabExpandedFolder
            }

            if((Test-Path $binsFolderExpanded\$versionDLLName) -eq $false)
            {
                LogMessage "Agent version file not found in input folder" $ERROR
                throw [System.IO.FileNotFoundException] "Agent version file not found"
            }
            $versionDLLObject = Get-Item $binsFolderExpanded\$versionDLLName
            $version = $versionDLLObject.VersionInfo.ProductVersion
            LogMessage $("Agent Version:" + $version) $INFORMATION

            return $version
        }

        # Sets the version of agent installed in the registry key
        function SetAgentRegistryVersion($newVersionValue)
        {
            $versionSubKey = "SOFTWARE\\Microsoft\\Microsoft Operations Manager\\3.0\\Setup"
            $versionRegValueName = "AgentVersion"

            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', "localhost")
            $regKey = $reg.OpenSubKey($versionSubKey, $true)
            $regKey.SetValue($versionRegValueName, $newVersionValue, [Microsoft.Win32.RegistryValueKind]::String)
        }

        #endregion

        #region Cab helper methods

        # Returns true if it finds at-least one cab file in the input folder
        function IsAnyUpdateCabPresent()
        {
            return (Test-Path $BinaryFolder\$updateCabNamePattern)
        }

        # Gets the version of the cab from the cab name. Cab name is expected in format: KB3117586-7.2.11644.0-NanoAgent.cab 
        function GetCabVersion($cabname)
        {
            $version = $cabname.Split("-")[1]
            return $version
        }

        # Returns true if version2 is higher than version1
        function IsVersionHigher([string]$version1, [string]$version2, [string]$cabname)
        {
            $v1Parts = $version1.Split(".")
            $v2Parts = $version2.Split(".")
            
            if($v2Parts.Length -ne 4)
            {
                # Build number not in expected format. Ignore this cab file
                LogMessage $("Cab name not in expected format: " + $cabName + " .Ignoring this cab file") $INFORMATION
                return $false
            }

            #Compare every part of the version starting from left
            for ($i=0; $i -lt $v1Parts.Length; $i++)
            {
                if($v2Parts[$i] -lt $v1Parts[$i])
                {
                    return $false
                }
                if($v2Parts[$i] -gt $v1Parts[$i])
                {
                    return $true
                }
            }
            
            # This means both versions are same
            return $false
        }

        # Get latest cab in input folder
        function GetLatestCabName()
        {
            $cabList = Get-ChildItem -Path $BinaryFolder\$updateCabNamePattern
            $latestVersion = "0.0.0.0"
            $latestCabName = ""

            foreach ($cab In $cabList)
            {
                $cabName = $cab.Name
                $cabCurVersion = GetCabVersion($cabName)
                if((IsVersionHigher $latestVersion $cabCurVersion $cabName) -eq $true)
                {
                    $latestCabName = $cabName
                    $latestVersion = $cabCurVersion
                }
            }
            return $latestCabName
        }

        # Expands the specified cab in input folder to specified subfolder in the install location on agent machine
        function CopyAndExpandCab([string]$SourceCabName, [string]$DestinationFolder)
        {
            # Copy cab to install location and expand inside install location
            if ((Test-Path $InstallLocationUNC\$SourceCabName) -eq $false)
            {
                Copy-Item $BinaryFolder\$SourceCabName $InstallLocationUNC
            }

            if ((Test-Path $DestinationFolder) -eq $false)
            {
                mkdir $DestinationFolder
            }
                
            $sourceCab = Join-Path $InstallLocationUNC $SourceCabName
            expand.exe $sourceCab -F:* $DestinationFolder

        }

        # Removes the expanded cab folders if it was created by the script
        function RemoveExpandedCabFolder()
        {
            if((Test-Path $RTMCabExpandedFolder) -eq $true)
            {
                LogMessage "Removing the expanded RTM cab folder" $INFORMATION
                Remove-Item -Path $RTMCabExpandedFolder -Recurse 
            }
            if((Test-Path $UpdateCabExpandedFolder) -eq $true)
            {
                LogMessage "Removing the expanded update cab folder" $INFORMATION
                Remove-Item -Path $UpdateCabExpandedFolder -Recurse 
            }
        }

        # Places the agent files from the specified cab expanded folder to the agent install location
        # Reads the files to be placed and the destination subdirectory in install directory from the specified filelist
        function PlaceAgentFilesFromExpandedCabFolder($cabExpandedFolder, $fileListName)
        {
            $BinaryList = Get-Content $cabExpandedFolder\$fileListName
            foreach ($line in $BinaryList)
            {
                if ($line.StartsWith("<Directory>"))
                {
                    $SubDirectory = $line.Split(' ')[1]
                    mkdir $InstallLocationUNC\$SubDirectory
                }
                else
                {
                    $BinaryFile = $line.Split(' ')[0]
                    $DestinationSubDirectory = $line.Split(' ')[1]
                    Copy-Item $cabExpandedFolder\$BinaryFile $InstallLocationUNC\$DestinationSubDirectory -Force
                }
            }
        }

        #endregion

        #endregion

        try
        {
            # Init some common variables
            #$NanoServerSystemDriveLetter = "C:"
            $AgentSubFolder = "Program Files\Microsoft Monitoring Agent\Agent"
            $InstallLocationUNC = "C:\$AgentSubFolder"

            $updateCabNamePattern = "*-NanoAgent.cab"
            $RTMCabName = "MOMNanoAgent.cab"

            $RTMBinsFolderName = "MOMNanoAgent_" + (Get-Date).ToString('yyMMdd_hhmmss')
            $UpdateBinsFolderName = "NanoAgentUpdate_" + (Get-Date).ToString('yyMMdd_hhmmss')
            $RTMBinaryFileListName = "BinaryFileList.txt"
            $UpdateBinaryFileListName = "UpdateBinaryFileList.txt"

            $RTMCabExpandedFolder = Join-Path $InstallLocationUNC $RTMBinsFolderName
            $UpdateCabExpandedFolder = Join-Path $InstallLocationUNC $UpdateBinsFolderName 
            $isUpdateCabPresent = $false

            # Check if it's a retry
            $installRetried = IsInstallRetried
            if($installRetried -eq $true)
            {
                LogMessage "It looks like a retry. Getting previous state." $INFORMATION
                #Read the variables
                GetPreviousInstallationState
            }
        }
        catch
        {
            LogMessage $("Error in init for install. " + $_.Exception.Message) $ERROR
            Exit
        }


        if($script:firewallOpened -eq 5)
        {
            LogMessage "Setting firewall rule" $INFORMATION
            try
            {
                netsh.exe advf firewall set rule group="Remote Event Log Management" new enable=yes
                $script:firewallOpened = 1
            }
            catch
            {
                $script:firewallOpened = 0
                LogMessage $("There was an error opening the firewall port. " + $_.Exception.Message) $ERROR
                Exit
            }
        }

        if($script:agentNotPreviouslyInstalled -eq 0)
        {
            LogMessage "Checking whether the agent is already installed" $INFORMATION
            
            # Checking whether the agent is already installed	  
            if ((Test-Path $InstallLocationUNC) -eq $true)
            {
                $script:agentNotPreviouslyInstalled = 0
                LogMessage "Agent directory already present in Nano Server. Please uninstall the agent using the Uninstallation script and then try again." $ERROR
                Exit
            }
            else
            {
                $script:agentNotPreviouslyInstalled = 1
            }
        }

        # Copy cabs and expand and place bins if copy bins or registry changes were not done earlier
        if(($script:foldersCreated -eq 0) -or ($script:registryChangesDone -eq 0))
        {
            LogMessage "Creating agent directory and populating it with binaries" $INFORMATION
            try
            {
                # Creating agent installation directory
                if ((Test-Path $InstallLocationUNC) -eq $false)
                {
                    mkdir $InstallLocationUNC
                }

                # Confirm the RTM cab is present
                if((Test-Path $BinaryFolder\$RTMCabName) -eq $false)
                {
                    throw [System.IO.FileNotFoundException] "RTM Nano agent cab file not found"
                }

                # Copy RTM cab to Agent Install location
                CopyAndExpandCab $RTMCabName $RTMCabExpandedFolder

                # Copy latest update cab (if any present) to Agent Install location
                $isUpdateCabPresent = IsAnyUpdateCabPresent
                if($isUpdateCabPresent -eq $true)
                {
                    # Get latest cab
                    $latestUpdateCabName = (GetLatestCabName)
                    LogMessage $("Latest nano agent update cab: " + $latestUpdateCabName + ". Will try expanding and installing this alongwith RTM payload.") $INFORMATION
                
                    # Copy and expand the cab 
                    CopyAndExpandCab $latestUpdateCabName $UpdateCabExpandedFolder
                }  

                # Populating the agent directory with the RTM binaries
                PlaceAgentFilesFromExpandedCabFolder $RTMCabExpandedFolder $RTMBinaryFileListName
                
                # Copy and replace with updated bins if any update cab found
                if($isUpdateCabPresent -eq $true)
                {
                    LogMessage "Copying the update binaries" $INFORMATION
                    PlaceAgentFilesFromExpandedCabFolder $UpdateCabExpandedFolder $UpdateBinaryFileListName
                }
                
                LogMessage "Expanding TMF" $INFORMATION
                $sourceTMFCab = Join-Path $InstallLocationUNC "Tools\TMF\OpsMgrTraceTMF.cab"
                $destTMF = Join-Path $InstallLocationUNC "Tools\TMF\OpsMgrTraceTMF.tmf"
                #Invoke-Command -ComputerName $NanoServerFQDN -ScriptBlock {expand.exe $args[0] -F:* $args[1]} -ArgumentList $sourceTMFCab,$destTMF
                #run above Invoke directly
                expand.exe $sourceTMFCab -F:* $destTMF

                LogMessage "Expanding resources" $INFORMATION
                $sourceResCab = Join-Path $InstallLocationUNC "Resources.cab"
                expand.exe $sourceResCab -F:* $InstallLocationUNC

                $script:foldersCreated = 1
            }
            catch
            {
                $script:foldersCreated = 0
                LogMessage $_.Exception.Message $ERROR
                RemoveExpandedCabFolder
                Exit
            }
        }


        if($script:registryChangesDone -eq 0)
        {
            LogMessage "Setting up and importing registry" $INFORMATION
            try
            {
                $SourceRegDir = $RTMCabExpandedFolder

                # Setting up the registry file for import
                #$VariableRegistry = Get-Content $SourceRegDir\VariableRegistryEntry.reg

                #Set-Content -Path $InstallLocationUNC\VariableRegistryEntry.reg -Value $VariableRegistry -ErrorAction Stop

                Copy-Item $SourceRegDir\StaticRegistryEntry.reg $InstallLocationUNC\StaticRegistryEntry.reg -Force -ErrorAction Stop

                $script = {			
                    $InstallLocationLocal = "C:\Program Files\Microsoft Monitoring Agent\Agent"
                    new-service -name HealthService -binaryPathName "$InstallLocationLocal\HealthService.exe" -dependson rpcss -displayName "@$InstallLocationLocal\HealthService.dll,-10500" -StartupType auto -Description "@$InstallLocationLocal\HealthService.dll,-10501"

                    $login = "NT AUTHORITY\NETWORK SERVICE"
                    $psw = "dummy"
                    $scuritypsw = ConvertTo-SecureString $psw -AsPlainText -Force
                    $mycreds = New-Object System.Management.Automation.PSCredential($login, $scuritypsw)
                    new-service -name AdtAgent -binaryPathName "$InstallLocationLocal\AdtAgent.exe" -dependson eventlog,dnscache -displayName "@$InstallLocationLocal\AdtAgent.exe,-500" -StartupType disabled -Description "@$InstallLocationLocal\AdtAgent.exe,-501" -credential $mycreds

                    #reg import $InstallLocationLocal\VariableRegistryEntry.reg
                    reg import $InstallLocationLocal\StaticRegistryEntry.reg

                    $acsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AdtAgent\Parameters"
                    $acl = Get-Acl -Path $acsKey
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("NT AUTHORITY\NETWORK SERVICE","FullControl","Allow")
                    $acl.SetAccessRule($rule)
                    $acl | Set-Acl -Path $acsKey

                    $acsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AdtAgent\Parameters\Cache"
                    $acl = Get-Acl -Path $acsKey
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("NT AUTHORITY\NETWORK SERVICE","FullControl","Allow")
                    $acl.SetAccessRule($rule)
                    $acl | Set-Acl -Path $acsKey

                    # Create empty [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups] key- required for service to Bootstrap to OMS.
                    LogMessage "Creating Management Groups registry key to bootstrap HealthService"
                    New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters -Name "Management Groups"
                }

                # Importing registry
                Invoke-Command -ScriptBlock $script
                $script:registryChangesDone = 1
            }
            # This is a known issue and also comes up in the install script. Would correct it for both the places together
            catch [System.Management.Automation.RemoteException]
            {
                $script:registryChangesDone = 1   
            }
            catch
            {
                $script:registryChangesDone = 0
                LogMessage $("Setting up and importing registry failed: " + $_.Exception.Message) $ERROR
                RemoveExpandedCabFolder
                Exit
            }

            try
            {
                # Set current agent version in registry
                $agentVersion = (GetAgentVersion)
                SetAgentRegistryVersion $agentVersion
            }
            catch
            {
                #ignore failures here as agent is almost installed
                LogMessage $("Setting agent version in registry failed: " + $_.Exception.Message) $INFORMATION        
            }
        }

        if($script:countersInstalled -eq 0)
        {
            # Installing connector performance counters
            LogMessage "Installing connector performance counters" $INFORMATION
            try
            {
                $installAgentPerformanceCounters = {
                    lodctr "C:\Program Files\Microsoft Monitoring Agent\Agent\MOMConnectorCounters.ini"
                }
                $installAgentPerformanceCounters 

                # Installing health service performance counters
                $installHealthServicePerformanceCounters = {
                    lodctr "C:\Program Files\Microsoft Monitoring Agent\Agent\HealthServiceCounters.ini"
                }
                $installHealthServicePerformanceCounters 
                $script:countersInstalled = 1
            }
            catch
            {
                $script:countersInstalled = 0
                LogMessage ("Failed to install performance counters: " + $_.Exception.Message) $ERROR
                RemoveExpandedCabFolder
                Exit
            }
        }

        LogMessage "Installation successfull!" $INFORMATION

        try
        {
            # Remove the expanded cab folder if it was created by the script
            RemoveExpandedCabFolder

            # We are done, remove the state file if exists   
            if(Test-Path $script:installStateFileName)
            {
                LogMessage "Removing state file"
                Remove-Item -Path $script:installStateFileName  -Force
            }
        }
        catch
        {
            LogMessage $("Agent installation successful but error in cleanup\logging." + $_.Exception.Message) $ERROR   
        }

        # We are done, saving the log file
        $installLog | out-file -filepath $script:installLogFileName -Force
    }

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