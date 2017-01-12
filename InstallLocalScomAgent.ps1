#param (
#[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$NanoServerFQDN,
#[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [string]$BinaryFolder)

$BinaryFolder = "C:\MMA-Nano-Agent"
#region Logging variables
$ERROR = 1
$INFORMATION = 2
#$NanoServer = $NanoServerFQDN
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
		# Opening firewalls. 
		#$openfirewallscript = {
			netsh.exe advf firewall set rule group="Remote Event Log Management" new enable=yes
		#}

		#Invoke-Command -ScriptBlock $openfirewallscript -ComputerName $NanoServerFQDN -ErrorAction Stop
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

# Attempt to start the service
#LogMessage "Attempting to start the service...!" $INFORMATION
#Get-Service -Name HealthService  | Set-Service -Status Running

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

<#
    .SYNOPSIS 
      Installs the SCOM based Microsoft Monitoring Agent (MMA) Agent for the Nano Server. 

    .EXAMPLE
     InstallNanoServerSCOMAgentOnline.ps1 -NanoServerFQDN MyNanoServerFQDN -BinaryFolder C:\MyNanoDrop\amd64\

	.DESCRIPTION
	 This script installs the SCOM Nano Agent RTM version on the given Nano Server machine. In case of any updates present inside NanoServer, expands the update cab to a temp folder and installs the updated Nano agent. 
     This script can run from both the management server and the nano server. This script has to be run with administrative privileges. 
     The user account which is used to run this script must also have administrative rights on the Nano Server (if running remotely). Also make sure that the SCOM powershell module is imported before running the script.
	 
#>
# SIG # Begin signature block
# MIIdtgYJKoZIhvcNAQcCoIIdpzCCHaMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrOVS6apVJG44DzczQg7JFxye
# wKugghhwMIIEwzCCA6ugAwIBAgITMwAAAJzu/hRVqV01UAAAAAAAnDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwMzMwMTkyMTMw
# WhcNMTcwNjMwMTkyMTMwWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjU4NDctRjc2MS00RjcwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzCWGyX6IegSP
# ++SVT16lMsBpvrGtTUZZ0+2uLReVdcIwd3bT3UQH3dR9/wYxrSxJ/vzq0xTU3jz4
# zbfSbJKIPYuHCpM4f5a2tzu/nnkDrh+0eAHdNzsu7K96u4mJZTuIYjXlUTt3rilc
# LCYVmzgr0xu9s8G0Eq67vqDyuXuMbanyjuUSP9/bOHNm3FVbRdOcsKDbLfjOJxyf
# iJ67vyfbEc96bBVulRm/6FNvX57B6PN4wzCJRE0zihAsp0dEOoNxxpZ05T6JBuGB
# SyGFbN2aXCetF9s+9LR7OKPXMATgae+My0bFEsDy3sJ8z8nUVbuS2805OEV2+plV
# EVhsxCyJiQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFD1fOIkoA1OIvleYxmn+9gVc
# lksuMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAFb2avJYCtNDBNG3nxss1ZqZEsphEErtXj+MVS/RHeO3TbsT
# CBRhr8sRayldNpxO7Dp95B/86/rwFG6S0ODh4svuwwEWX6hK4rvitPj6tUYO3dkv
# iWKRofIuh+JsWeXEIdr3z3cG/AhCurw47JP6PaXl/u16xqLa+uFLuSs7ct7sf4Og
# kz5u9lz3/0r5bJUWkepj3Beo0tMFfSuqXX2RZ3PDdY0fOS6LzqDybDVPh7PTtOwk
# QeorOkQC//yPm8gmyv6H4enX1R1RwM+0TGJdckqghwsUtjFMtnZrEvDG4VLA6rDO
# lI08byxadhQa6k9MFsTfubxQ4cLbGbuIWH5d6O4wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCBhwwggQE
# oAMCAQICEzMAAAB1jqiVpC+KZ5YAAAAAAHUwDQYJKoZIhvcNAQELBQAwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xNjA1MDkyMjA2NDNaFw0xNzA4
# MDkyMjA2NDNaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQT9vZFCAUjfz7MBFlwUfp
# ZR0A8yIksUdiG+AbJQM+pb54q0LS2Cwk3U7NUPoT4TpaLx/rI0X35vwfmQS+L0cg
# F5hzXrjbZOGZ89Dafcycy1V7LI9OGOPAYBK4HdSotajrC/iAtYNbi35DwYhdiEpa
# 6RL2/+vdfTSahzBECVeM3RkPi/DCnbqcutFYRe2QBHFmgiHvnyNDyCkTUeoijUI3
# feU4p5iaDqpIuweRF36qccaSn2W1oeVpVlSXFPGGmIfa822cIZUIdPyPZBYtT60V
# ytsZa24D2yYucaUnhpeKiZEkOkJIOikR4OWTIC6TYTDGi+Ejnm//orSmuTmbBA1Z
# AgMBAAGjggGLMIIBhzArBgNVHSUEJDAiBggrBgEFBQcDAwYKKwYBBAGCN0wIAQYK
# KwYBBAGCN0wUATAdBgNVHQ4EFgQUhOVssrNQGAQkDzIMmFIAB6fCy4IwUQYDVR0R
# BEowSKRGMEQxDTALBgNVBAsTBE1PUFIxMzAxBgNVBAUTKjU0ODIyK2NmOTU1Yzk0
# LTRlM2QtNDNhNi04M2YzLWFjMWE1ZTZjMDlhNTAfBgNVHSMEGDAWgBRIbmTlUAXT
# gqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDgu
# Y3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDct
# MDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAG4s7itCZwil
# gYuAvw+2GGAE0woflXoUN8K/iUCBhCWmCYkn6NbvgxvZHx4yzXN3oSeT9WscuNFI
# nhN0xzHiFeznp8k/niWCss6PIioMYox0ibYqnZAi7ILJrengTUK5q87JJ2GJ2uT4
# kPt3+WYHbRIvJ/2Tztxb4tAIoUkaRZ6RXbTGvSTtK2JRydH/NUvucsdtoZArwLsu
# PndHB+6ZjjDXsLJX7YvdkQEQbcwEm4NuFiXa7krTEnAM5C1DcyIBvbiEpIIBt8Mo
# Mm4/xypZmEKRdAwtiTYqVuA/b74XAlynylJzJVzoFN6yQa+Pai2iLRWGdJNDagrZ
# rKvekxRgZOS5Ap7wCezd7zHPid1EVr2KOJBXi+nbPRCagmX0Zm8+TdUyxmmMiuEZ
# uwC9WBFyc6qHxenWy+KGOWLB7QUetCj+/ptu5TKp65DRTWXOp6ZIP9g2cqlMqxxO
# jVY/dGj286/2GjxYnQHyImE6fr4l0AbkXpS9V8iRUidLwzno/dzZABbgQMtWGDzf
# 7rOdn0E3wz3FvG7tL762Q8jZZIi3y3i928kd+cP7lcIMccgS3v4GriKb22h3ECQo
# 6r7cdlDNlVo9UN5bJxnp0RdSntjpUWhd4cx0GV4B2PDiqaGTnFAB+OL1ga3KF5mX
# MtOZqxejJNxyMaP0lIuyNquoeMDocrl6MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAA
# AzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0
# aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNy
# b3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6
# f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IK
# LMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpc
# oRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAf
# TVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+
# /jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/
# jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+
# UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwY
# uER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W
# 7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlM
# xdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEA
# AaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoX
# NzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx
# 0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3Js
# MF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0
# MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRt
# MEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0
# AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou
# 09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/
# IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLp
# ZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWlu
# WpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLw
# xS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3
# dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a
# 8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7e
# ZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiV
# H6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0E
# TI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmb
# dlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCBLAwggSsAgEBMIGVMH4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBD
# b2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAB1jqiVpC+KZ5YAAAAAAHUwCQYFKw4D
# AhoFAKCBxDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgEL
# MQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU/ui/nOxiKGyTVYOqsA35
# OxYe/NwwZAYKKwYBBAGCNwIBDDFWMFSgNoA0AE0AaQBjAHIAbwBzAG8AZgB0ACAA
# TQBvAG4AaQB0AG8AcgBpAG4AZwAgAEEAZwBlAG4AdKEagBhodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAZ+49kNg+hmoYdrXRrjdH0dOy
# 9t8vyUbGmAgvB543ynr0L/03PAqPMSmQAlXXrjt8rrcvUAsYKoOS44OZ4OJ5xrDL
# uL+yK4qV4AtAtfiSbvSoaJ3yXd3mzeoUo+FLF+lSvSPHvvcxx0Lt0d1EP28ccSg+
# DJ8mcxNgPaFiyhGduE7oZqz2GldQuf7bUQSw0wdlZkW3HS5/wjYSEY3asM1Natj+
# g/WhtiePY7I2R+ytc652ZQuiMBc17K1XrunrOj165q0hQlZdI4yrTlwvuiZrKsbe
# V87NEbmt5C/HT77yXahF2YtxPCkCQXG6OESvuBqsyhf2Lu+TUZ1BN3n8F9c7O6GC
# AigwggIkBgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0ECEzMAAACc7v4UValdNVAAAAAAAJwwCQYFKw4DAhoFAKBdMBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDcwNjEwMjUz
# MlowIwYJKoZIhvcNAQkEMRYEFNYNm8ngeeefkCNxq3WoYEZTGY5BMA0GCSqGSIb3
# DQEBBQUABIIBALqv+lNAAZGbeTkXDGEQAFfvdG52lmKaqSG/Ufqxa+EZ1DGtIOGM
# RkVL+IQ2z8S/EPvdtHAtKHcuRZ83z8uU6ir5eDKmvxR3r6H/Rk+WAY4q5GsosL0k
# xZvNaTHgnpeR2eEcQ7iNwGTfrHkDGPn+LU64lwd0Mp0W3iSczbT6gHkwBl/PKkAN
# KONbvDPBGwVF1G2FtO+uaJpfjjCcfIPz/vMeev+QEQqbi8q5JM9/JfN6x0oI4sjO
# 3NODgqv7qV/4lmxJtA3sP1HHkgI2dP6GTfYh3wAXxLLtZ6RICCajwwGJNv1ggRBE
# DrWRJGh0BMMxRqhfZIpbCWnNNM3ItyakmLc=
# SIG # End signature block
