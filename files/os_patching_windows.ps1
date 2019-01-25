#Requires -Version 3.0

[CmdletBinding(DefaultParameterSetName = 'DefaultUpdateService')]
param(
    [Parameter(ParameterSetName = 'WindowsUpdate')]
    [Parameter(ParameterSetName = 'MicrosoftUpdate')]
    [Parameter(ParameterSetName = 'DefaultUpdateService')]
    [Switch]
    $RefreshFacts,

    [Parameter(ParameterSetName = 'WindowsUpdate')]
    [Parameter(ParameterSetName = 'MicrosoftUpdate')]
    [Parameter(ParameterSetName = 'DefaultUpdateService')]
    [Switch]
    $SecurityOnly,

    [Parameter(ParameterSetName = 'WindowsUpdate')]
    [Switch]
    $UseWindowsUpdate,
    
    [Parameter(ParameterSetName = 'MicrosoftUpdate')]
    [Switch]
    $UseMicrosoftUpdate
)

#$VerbosePreference = "continue"

#strict mode
Set-StrictMode -Version 2

#
# functions
#

Function Get-WUServiceManager {
    New-Object -ComObject 'Microsoft.Update.ServiceManager'
}

Function Get-WUSession {
    New-Object -ComObject 'Microsoft.Update.Session' 
}

Function Get-WUUpdateCollection {
    New-Object -ComObject Microsoft.Update.UpdateColl
}

Function Get-WUServiceManager {
    <#
	.SYNOPSIS
	    Show Service Manager configuration.

	.DESCRIPTION
	    Use Get-WUServiceManager to get available configuration of update services.
                              		
	.EXAMPLE
		Show currently available Windows Update Services on machine.
	
		PS C:\> Get-WUServiceManager

		ServiceID                            IsManaged IsDefault Name
		---------                            --------- --------- ----
		9482f4b4-e343-43b6-b170-9a65bc822c77 False     False     Windows Update
		7971f918-a847-4430-9279-4a52d1efe18d False     False     Microsoft Update
		3da21691-e39d-4da6-8a4b-b43877bcb1b7 True      True      Windows Server Update Service
		13df3d8f-78d7-4eb8-bb9c-2a101870d350 False     False     Offline Sync Service2
		a8f3b5e6-fb1f-4814-a047-2257d39c2460 False     False     Offline Sync Service

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Add-WUOfflineSync
        Remove-WUOfflineSync
	#>
    [OutputType('PSWindowsUpdate.WUServiceManager')]
    [CmdletBinding(
        SupportsShouldProcess = $True,
        ConfirmImpact = "Low"
    )]
    Param()
	
    Begin {
        $User = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

        if (!$Role) {
            Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
        } #End If !$Role	
    }
	
    Process {
        If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME, "Get Windows Update ServiceManager")) {
            $objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"

            $ServiceManagerCollection = @()
            Foreach ($objService in $objServiceManager.Services) {
                $objService.PSTypeNames.Clear()
                $objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
						
                $ServiceManagerCollection += $objService
            } #End Foreach $objService in $objServiceManager.Services
			
            Return $ServiceManagerCollection
        } #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Get Windows Update ServiceManager")		

    } #End Process
	
    End {}
} #In The End :)

Function Get-Pendingreboot {
    #Copied from http://ilovepowershell.com/2015/09/10/how-to-check-if-a-server-needs-a-reboot/
    #Adapted from https://gist.github.com/altrive/5329377
    #Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>

    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($null -ne $status) -and $status.RebootPending) {
            return $true
        }
    }
    catch {}
 
    return $false
}

#
# vars
#

# Update Criteria
$updateCriteria = "IsInstalled=0 and IsHidden=0"

#start time
$startTime = [System.DateTime]::Now

#paths to facts
$dataDir = 'C:\ProgramData\os_patching'
$updateFile = Join-Path -Path $dataDir -ChildPath 'package_updates'
$secUpdateFile = Join-Path -Path $dataDir -ChildPath 'security_package_updates'
$rebootReqdFile = Join-Path -Path $dataDir -ChildPath  'reboot_required'

Write-Verbose "Update criteria is: $updateCriteria"

Write-Verbose "Creating Objects"

#create update session
$updateSession = Get-WUSession

#create update searcher
$updateSearcher = $updateSession.CreateUpdateSearcher()

Write-Verbose "Selecting update service manager"

# https://docs.microsoft.com/en-us/windows/desktop/api/wuapicommon/ne-wuapicommon-tagserverselection
# https://docs.microsoft.com/en-us/previous-versions/windows/desktop/aa387280%28v%3dvs.85%29
#
# ssDefault        = 0,
# ssManagedServer  = 1,
# ssWindowsUpdate  = 2,
# ssOthers         = 3

if ($UseWindowsUpdate) {
    Write-Verbose "Using Microsoft Update"
    $updateSearcher.ServerSelection = 2 #ssWindowsUpdate
}
elseif ($UseMicrosoftUpdate) {
    Write-Verbose "Using Windows Update"
    $updateSearcher.ServerSelection = 3 #ssOthers
    #
    # MORE CODING TO DO HERE TO SET SERVICE ID :)
    #
}
else {
    $defaultUpdateService = Get-WUServiceManager | Where-Object {$_.IsDefaultAUService}
    Write-Verbose "Using default update service - $($defaultUpdateService.name)"
}

Write-Verbose "Performing update search"
$searchResults = $updateSearcher.Search($updateCriteria)

# get updates
$updates = $searchResults.updates

$updateCount = $updates.count

if ($updateCount -gt 0) {
    Write-Verbose "Detected $updateCount updates."

    if ($RefreshFacts) {
        # output list of required updates
        $updates | Select-Object -ExpandProperty Title | Out-File $updateFile -Force -Encoding ascii

        # filter to security updates and output
        $updates | Select-Object Title, @{N = "categories"; E = {$_.Categories | Select-Object -expandproperty Name}} | `
            Where-Object {$_.categories -contains "Security Updates"} | Select-Object -ExpandProperty Title | Out-File $secUpdateFile -Force -Encoding ascii

        Get-Pendingreboot | Out-File $rebootReqdFile -Force -Encoding ascii

        #upload facts
        Write-Verbose "Uploading puppet facts"
        $puppetCmd = Join-Path $env:ProgramFiles -ChildPath "Puppet Labs\Puppet\bin\puppet.bat"
        & $puppetCmd facts upload
    }
    else {

        # get updates to download
        # only those where IsDownloaded is false
        $updatesNotDownloaded = $updates | Where-Object {$_.IsDownloaded -eq $false}

        if ($updatesNotDownloaded) {
            # Create update collection...
            $updateDownloadCollection = Get-WUUpdateCollection

            # ...Add updates to it
            foreach ($update in $updatesNotDownloaded) {
                [void]$updateDownloadCollection.Add($update)
            }

            Write-Verbose "Downloading $($updateDownloadCollection.Count) updates."

            # Create update downloader
            $updateDownloader = $updateSession.CreateUpdateDownloader()

            # Set updates to download
            $updateDownloader.Updates = $updateDownloadCollection

            # and download 'em!
            [void]$updateDownloader.Download()
            Write-Verbose "Download of $($updateDownloadCollection.Count) updates completed."
        }
        else {
            Write-Verbose "All updates are already downloaded."
        }

        #end time
        $endTime = [System.DateTime]::Now

        #result
        [pscustomobject]@{
            StartTime = $startTime
            EndTime   = $endTime
        }

    }
}
else {
    Write-Verbose "No updates detected."
}

