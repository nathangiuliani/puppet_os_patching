#Requires -Version 3.0

[CmdletBinding()]
param(
    [Switch]$RefreshFacts,
    [Switch]$SecurityOnly,
    [String]$updateCriteria = "IsInstalled=0 and IsHidden=0"
)

$VerbosePreference = "continue"

# strict mode
Set-StrictMode -Version 2

# clear any errors
$error.Clear()

# Set error action preference to stop. Trap ensures all errors caught
$ErrorActionPreference = "stop"

# trap
trap {
    # verbose output for console
    Write-Verbose "Unhandled exception caught:"
    Write-Verbose $_.exception.ToString()                                          # Error message
    Write-Verbose $_.invocationinfo.positionmessage.ToString()                     # Line the error was generated on

    # JSON output for bolt etc.
    $trapDetails = "Failed due to trap - {0} {1}" -f $_.exception.ToString() , $_.invocationinfo.positionmessage.ToString() 

    [PSCustomObject]@{
        Status = "Failure"
        Details = $trapDetails
    } | ConvertTo-Json
}

#
# functions
#

Function Get-WUSession {
    # returns a microsoft update session object
    Write-Debug "Get-WUSession: Creating update session object"
    New-Object -ComObject 'Microsoft.Update.Session' 
}

Function Get-WUUpdateCollection {
    #returns a microsoft update update collection object
    New-Object -ComObject Microsoft.Update.UpdateColl
}

Function Get-PendingReboot {
    #Copied from http://ilovepowershell.com/2015/09/10/how-to-check-if-a-server-needs-a-reboot/
    #Adapted from https://gist.github.com/altrive/5329377
    #Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>

    $rebootPending = $false

    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { $rebootPending = $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { $rebootPending = $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { $rebootPending = $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($null -ne $status) -and $status.RebootPending) {
            $rebootPending = $true
        }
    }
    catch {}
 
    if ($rebootPending) { Write-Verbose "A reboot is required" }

    # return result
    $rebootPending
}

Function Invoke-RefreshPuppetFacts{
    # refreshes puppet facts used by os_patching module
    # inputs - $UpdateSession - microsoft update session object
    # outpts - none, saves puppet fact files only
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$UpdateSession
    )
    # refresh puppet facts

    Write-Verbose "Refresing puppet facts"

    $allUpdates = Get-UpdateSearch($UpdateSession)
    $securityUpdates = Get-SecurityUpdates($allUpdates)

    #paths to facts
    $dataDir = 'C:\ProgramData\os_patching'
    $updateFile = Join-Path -Path $dataDir -ChildPath 'package_updates'
    $secUpdateFile = Join-Path -Path $dataDir -ChildPath 'security_package_updates'
    $rebootReqdFile = Join-Path -Path $dataDir -ChildPath  'reboot_required'

    # output list of required updates
    $allUpdates | Select-Object -ExpandProperty Title | Out-File $updateFile -Encoding ascii

    # filter to security updates and output
    $securityUpdates | Select-Object -ExpandProperty Title | Out-File $secUpdateFile -Encoding ascii

    # get pending reboot details
    Get-PendingReboot | Out-File $rebootReqdFile -Encoding ascii

    # upload facts
    Write-Verbose "Uploading puppet facts"
    $puppetCmd = Join-Path $env:ProgramFiles -ChildPath "Puppet Labs\Puppet\bin\puppet.bat"
    & $puppetCmd facts upload
}

Function Get-UpdateSearch{
    # performs an update search
    # inputs: update session
    # outputs: updates from search result
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$UpdateSession
    )

    Write-Verbose "Update search criteria is: $updateCriteria"

    # create update searcher
    $updateSearcher = $UpdateSession.CreateUpdateSearcher()

    Write-Verbose "Performing update search"

    # perform search and select Update property
    $updates = $updateSearcher.Search($updateCriteria).Updates

    $updateCount = $updates.count

    Write-Verbose "Detected $updateCount updates are required in total (including security)"

    # return updates
    $updates
}

Function Get-SecurityUpdates{
    # filters update list to security only
    # inputs - update list from an update search
    # outputs - filtered list
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Updates
    )
    # filter to security updates
    $secUpdates = $Updates | Select-Object Title, @{N = "categories"; E = {$_.Categories | Select-Object -expandproperty Name}} | Where-Object {$_.categories -contains "Security Updates"}

    # count them
    $secUpdateCount = $secUpdates.count

    Write-Verbose "Detected $secUpdateCount security updates are required"

    # return security updates
    $secUpdates
}

Function Invoke-UpdateRun{
    # perform an update run
    # inputs - update session
    # outputs - update run results
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$UpdateSession
    )

    # search for (all) updates
    $allUpdates = Get-UpdateSearch($UpdateSession)

    # filter to security updates if switch parameter is set
    if ($SecurityOnly) {
        $updatesToInstall = Get-SecurityUpdates -Updates $allUpdates | Select-Object -first 3
    }
    else {
        $updatesToInstall = $allUpdates | Select-Object -first 3
    }

    # get update count
    $updateCount = @($updatesToInstall).count # ensure it's an array so count property exists

    if ($updateCount -gt 0) { 
        # we need to install updates

        # download updates if needed. No output from this function
        Invoke-DownloadUpdates -UpdateSession $UpdateSession -UpdatesToDownload $updatesToInstall

        # Install Updates. Pass (return) output to the pipeline
        Invoke-InstallUpdates -UpdateSession $UpdateSession -UpdatesToInstall $updatesToInstall
    } else {
        Write-Verbose "No updates required"

        # build final result for output
        [PSCustomObject]@{
            Status = "No updates required"
        }
    }
}

Function Invoke-DownloadUpdates{
    # download updates if required
    # inputs  - UpdateSession     - update session
    #         - UpdatesToDownload - update collection (of updates to download)
    # outputs - none
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$UpdateSession,
        [Parameter(Mandatory = $true)]$UpdatesToDownload
    )

    # download updates if necessary, i.e. only those where IsDownloaded is false
    $updatesNotDownloaded = $UpdatesToDownload | Where-Object {$_.IsDownloaded -eq $false}

    if ($updatesNotDownloaded) {
        # Create update collection...
        $updateDownloadCollection = Get-WUUpdateCollection

        # ...Add updates to it
        foreach ($update in $updatesNotDownloaded) {
            [void]$updateDownloadCollection.Add($update) # void stops output to console
        }

        Write-Verbose "Downloading $($updateDownloadCollection.Count) updates"

        # Create update downloader
        $updateDownloader = $updateSession.CreateUpdateDownloader()

        # Set updates to download
        $updateDownloader.Updates = $updateDownloadCollection

        # and download 'em!
        [void]$updateDownloader.Download()
        Write-Verbose "Download completed"
    }
    else {
        Write-Verbose "All updates are already downloaded"
    }
}

Function Invoke-InstallUpdates{
    # install updates
    # inputs  - UpdateSession    - update session
    #         - UpdatesToInstall - update collection (of updates to install)
    # outputs - pscustomobject with install results
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$UpdateSession,
        [Parameter(Mandatory = $true)]$UpdatesToInstall
    )

    # get update count
    $updateCount = @($updatesToInstall).count # ensure it's an array so count property exists

    Write-Verbose "Installing $updateCount updates"

    # create a counter var starting at 1
    $counter = 1

    # create blank array for result output
    $updateInstallResults = @()

    foreach ($update in $updatesToInstall) {

        Write-Verbose "Installing update $($counter): $($update.Title)"

        # create update collection...
        $updateInstallCollection = Get-WUUpdateCollection

        # ...Add the current update to it
        [void]$updateInstallCollection.Add($update) # void stops output to console

        # create update installer
        $updateInstaller = $updateSession.CreateUpdateInstaller()

        # Add update collection to the installer
        $updateInstaller.Updates = $updateInstallCollection

        # Install updates and capture result
        $updateInstallResult = $updateInstaller.Install()

        # Convert ResultCode to something readable
        $updateStatus = switch ($updateInstallResult.ResultCode) {
            0 { "NotStarted" }
            1 { "InProgress" }
            2 { "Succeeded" }
            3 { "SucceededWithErrors" }
            4 { "Failed" }
            5 { "Aborted" }
            default {"unknown"}
        }

        # build object with result for this update and add to array
        $updateInstallResults += [pscustomobject]@{
            Title          = $update.Title
            Status         = $updateStatus
            HResult        = $updateInstallResult.HResult
            RebootRequired = $updateInstallResult.RebootRequired
        }

        # increment counter
        $counter++
    }

    # build final result for output
    [PSCustomObject]@{
        Status = "Success"
        InstallResults = $updateInstallResults
        RebootRequired = Get-PendingReboot
    } 
}


#
# vars
#

Write-Verbose "OS_Patching_Windows script started"

#create update session
$wuSession = Get-WUSession

if ($RefreshFacts) {
    # refresh facts mode
    Invoke-RefreshPuppetFacts -UpdateSession $wuSession
} else {
    # invoke update run    
    Invoke-UpdateRun -UpdateSession $wuSession
}           

Write-Verbose "OS_Patching_Windows script finished"