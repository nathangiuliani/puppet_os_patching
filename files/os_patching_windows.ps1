#Requires -Version 3.0

<#
.SYNOPSIS
Installs windows updates, or refreshes update related facts, for the puppet module os_patching.

.DESCRIPTION
Installs windows updates, or refreshes update related facts, for the puppet module os_patching. This script is intended to be run as part of the os_patching module, however it will also function standalone.

The download and install APIs are not available over a remote PowerShell session (e.g. through Puppet Bolt). To overcome this, the script may launch the patching as a scheduled task running as local system.

.PARAMETER RefreshFacts
Refresh/re-generate puppet facts for this module.

.PARAMETER ForceLocal
Force running in local mode. This mode is intended for use when running in a local session, (e.g. running as a task with Puppet Enterprise over PCP). If neither this option or ForceSchedTask is specified, the script will check to see if it can run the patching code locally, if not, it will run as a scheduled task.

.PARAMETER ForceSchedTask
Force running in scheduled task mode. This indended for use in a remote session, (e.g. running as a task with Puppet Bolt over WinRM). If neither this option or ForceSchedTask is specified, the script will check to see if it can run the patching code locally, if not, it will run as a scheduled task.

.PARAMETER SecurityOnly
Switch, when set the script will only install updates with a category that includes Security Update.

.PARAMETER UpdateCriteria
Criteria used for update detection. This ultimately drives which updates will be installed. The detault is "IsInstalled=0 and IsHidden=0" which should be suitable in most cases, and relies on your upstream update approvals. Note that this is not validated, if the syntax is not validated the script will fail. See MSDN doco for valid syntax - https://docs.microsoft.com/en-us/windows/desktop/api/wuapi/nf-wuapi-iupdatesearcher-search.

.PARAMETER OnlyXUpdates
Install only the first X numbmer of updates. For testing purposes.
#>


[CmdletBinding(defaultparametersetname="InstallUpdates")]
param(
    # refresh fact mode
    [Parameter(ParameterSetName = "RefreshFacts")]
    [Switch]$RefreshFacts,

    # force local method
    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Switch]$ForceLocal,

    # force scheduled task method
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Switch]$ForceSchedTask,

    # only install security updates
    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Parameter(ParameterSetName = "InstallUpdates")]
    [Switch]$SecurityOnly,

    # update criteria
    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Parameter(ParameterSetName = "RefreshFacts")]
    [String]$UpdateCriteria = "IsInstalled=0 and IsHidden=0",

    # only install the first x updates
    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Parameter(ParameterSetName = "InstallUpdates")]
    [Int32]$OnlyXUpdates
)


# strict mode
Set-StrictMode -Version 2

# clear any errors
$error.Clear()

# Set error action preference to stop. Trap ensures all errors caught
$ErrorActionPreference = "stop"

Function Invoke-AsCommand {
    Write-Verbose "Running as script block"

    Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $scriptBlockParams    
}


Function Invoke-AsScheduledTask {
    [CmdletBinding()]
    param (
    [string]$TaskName = "os_patching job",
    [int32]$WaitMS = 500
    )

    Write-Verbose "Registering scheduled task"

    # define scheduled task trigger
    $trigger = @{
        Frequency = "Once" # (or Daily, Weekly, AtStartup, AtLogon)
        At        = $(Get-Date).AddSeconds(2) # in 2 seconds time
    }

    #
    # TODO: pass through verbosepreference
    #

    Register-ScheduledJob -name $TaskName -ScriptBlock $scriptBlock -ArgumentList $scriptBlockParams -Trigger $trigger | Out-Null

    # Task state reference: https://docs.microsoft.com/en-us/windows/desktop/taskschd/registeredtask-state
    $taskStates = @{
        0 = "Unknown"
        1 = "Disabled"
        2 = "Queued"
        3 = "Ready"
        4 = "Running"
    }
    # Links to task result codes:
    #   https://docs.microsoft.com/en-us/windows/desktop/TaskSchd/task-scheduler-error-and-success-constants
    #   http://www.pgts.com.au/cgi-bin/psql?blog=1803&ndx=b001 (with decimal codes)

    Write-Verbose "Waiting for scheduled task to start"

    $taskScheduler = New-Object -ComObject Schedule.Service
    $taskScheduler.Connect("localhost")
    $psTaskFolder = $taskScheduler.GetFolder("\Microsoft\Windows\PowerShell\ScheduledJobs")

    while ($psTaskFolder.GetTask($TaskName).State -ne 4) {
        "Task Status: {0} - Waiting another {1}ms for scheduled task to start" -f $taskStates[$psTaskFolder.GetTask($TaskName).State], $WaitMS | Write-Verbose
        Start-Sleep -Milliseconds $WaitMS
    }

    Write-Verbose "Invoking wait-job to wait for job to finish and get job output"

    $job = $null
    while ($null -eq $job) {
        try {
            $job = wait-job $TaskName
        }
        catch [System.Management.Automation.PSArgumentException] {
            # wait-job can't see the job yet, this takes some time
            # so wait a bit longer for wait-job to work!
            "  Waiting another $($WaitMS)ms for wait-job to pick up the job" | Write-Verbose
            Start-Sleep -Milliseconds $WaitMS
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($job.Output -eq $null -and $sw.ElapsedMilliseconds -lt 60000) {
        "Waiting for job output to populate" | Write-Verbose
        Start-Sleep -Milliseconds $WaitMS
    }

    Write-Verbose "Deleting scheduled task"

    $running_tasks = @($taskScheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName })
    foreach ($task_to_stop in $running_tasks) {
        "Task seems to be running still, stopping it" | Write-Verbose
        $task_to_stop.Stop()
    }

    Unregister-ScheduledJob $TaskName

    #return job output
    $job.Output

    #write any verbose output
    $job.Verbose | Write-Verbose
    
    #return any error output
    $job.Error | Write-Error
}

# trap
trap {
    # verbose output for console
    Write-Verbose "Unhandled exception caught:"
    Write-Verbose $_.exception.ToString()                                          # Error message
    Write-Verbose $_.invocationinfo.positionmessage.ToString()                     # Line the error was generated on

    # JSON output for bolt etc.
    $trapDetails = "Failed due to trap - {0} {1}" -f $_.exception.ToString() , $_.invocationinfo.positionmessage.ToString() 

    [PSCustomObject]@{
        Status  = "Failure"
        Details = $trapDetails
    } | ConvertTo-Json
}

# script block for local or scheduled task
# main script code is actually here!
$scriptBlock = {

    [CmdletBinding()]

    # one parameter - a psobject containing the actual script arguments!
    param([psobject]$Params)

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
            Status  = "Failure"
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

    Function Invoke-RefreshPuppetFacts {
        # refreshes puppet facts used by os_patching module
        # inputs - $UpdateSession - microsoft update session object
        # outpts - none, saves puppet fact files only
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]$UpdateSession
        )
        # refresh puppet facts

        Write-Verbose "Refreshing puppet facts"

        $allUpdates = Get-UpdateSearch($UpdateSession)
        $securityUpdates = Get-SecurityUpdates($allUpdates)

        #paths to facts
        $dataDir = 'C:\ProgramData\os_patching'
        $updateFile = Join-Path -Path $dataDir -ChildPath 'package_updates'
        $secUpdateFile = Join-Path -Path $dataDir -ChildPath 'security_package_updates'
        $rebootReqdFile = Join-Path -Path $dataDir -ChildPath  'reboot_required'

        # create os_patching data dir if required
        if (-not (Test-Path $dataDir)) { [void](New-Item $dataDir -ItemType Directory) }

        # output list of required updates
        $allUpdates | Select-Object -ExpandProperty Title | Out-File $updateFile -Encoding ascii

        # filter to security updates and output
        $securityUpdates | Select-Object -ExpandProperty Title | Out-File $secUpdateFile -Encoding ascii

        # get pending reboot details
        Get-PendingReboot | Out-File $rebootReqdFile -Encoding ascii

        # upload facts
        Write-Verbose "Uploading puppet facts"
        $puppetCmd = Join-Path $env:ProgramFiles -ChildPath "Puppet Labs\Puppet\bin\puppet.bat"
        & $puppetCmd facts upload --color=false
    }

    Function Get-UpdateSearch {
        # performs an update search
        # inputs: update session
        # outputs: updates from search result
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$UpdateSession
        )

        Write-Verbose "Update search criteria is: $($Params.UpdateCriteria)"

        # create update searcher
        $updateSearcher = $UpdateSession.CreateUpdateSearcher()

        Write-Verbose "Performing update search"

        # perform search and select Update property
        $updates = $updateSearcher.Search($Params.UpdateCriteria).Updates

        $updateCount = $updates.count

        Write-Verbose "Detected $updateCount updates are required in total (including security)"

        # return updates
        $updates
    }

    Function Get-SecurityUpdates {
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
        if ($secUpdates) {
            $secUpdateCount = $secUpdates.count

            Write-Verbose "Detected $secUpdateCount security updates are required"

            # return security updates
            $secUpdates
        }
    }

    Function Invoke-UpdateRun {
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
        if ($Params.SecurityOnly) {
            $updatesToInstall = Get-SecurityUpdates -Updates $allUpdates
        }
        else {
            $updatesToInstall = $allUpdates
        }

        if ($Params.OnlyXUpdates -gt 0) {
            Write-Verbose "Selecting only the first $Params.OnlyXUpdates updates"
            $updatesToInstall = $updatesToInstall | Select-Object -First $Params.OnlyXUpdates
        }

        # get update count
        $updateCount = @($updatesToInstall).count # ensure it's an array so count property exists

        if ($updateCount -gt 0) { 
            # we need to install updates

            # download updates if needed. No output from this function
            Invoke-DownloadUpdates -UpdateSession $UpdateSession -UpdatesToDownload $updatesToInstall

            # Install Updates. Pass (return) output to the pipeline
            Invoke-InstallUpdates -UpdateSession $UpdateSession -UpdatesToInstall $updatesToInstall
        }
        else {
            Write-Verbose "No updates required"

            # build final result for output
            [PSCustomObject]@{
                Status = "No updates required"
            }
        }
    }

    Function Invoke-DownloadUpdates {
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

    Function Invoke-InstallUpdates {
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
            Status         = "Success"
            InstallResults = $updateInstallResults
            RebootRequired = Get-PendingReboot
        } 
    }

    Write-Verbose "OS_Patching_Windows scriptblock started"

    #create update session
    $wuSession = Get-WUSession

    if ($Params.RefreshFacts) {
        # refresh facts mode
        Invoke-RefreshPuppetFacts -UpdateSession $wuSession
    }
    else {
        # invoke update run, convert results to JSON and send down the pipeline
        Invoke-UpdateRun -UpdateSession $wuSession | ConvertTo-Json
    } 
    
    Write-Verbose "OS_Patching_Windows scriptblock finished"

}

# main code
Write-Verbose "OS_Patching_Windows script started"

#build parameter PSCustomObject for passing to the scriptblock
    $scriptBlockParams = [PSCustomObject]@{
        RefreshFacts   = $RefreshFacts 
        SecurityOnly   = $SecurityOnly    
        UpdateCriteria = $UpdateCriteria    
        OnlyXUpdates   = $OnlyXUpdates
    }

    Write-Verbose "Trying to access the windows update API locally..."

    try {
        # try to create a windows update downloader
        (New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownloader() | Out-Null
        $localSession = $true
        Write-Verbose "  Accessing the windows update API locally succeeded"
    } catch [System.Management.Automation.MethodInvocationException] {
        $localSession = $false
        Write-Verbose "  Accessing the windows update API locally failed"
    }

    # run either in an invoke-command or a scheduled task based on the result above and provided command line parameters
    # refresh facts is always in an invoke-command as the update search API works in a remote session
    if ((($localSession -or $ForceLocal) -and -not $ForceSchedTask) -or $RefreshFacts) {
        if ($ForceLocal) { Write-Verbose "Forced running locally, this may fail if in a remote session" }
        Invoke-AsCommand
    } else {
        if ($ForceSchedTask) { Write-Verbose "Forced running in a scheduled task, this may not be necessary if running in a local session" }
        Invoke-AsScheduledTask
    }

Write-Verbose "OS_Patching_Windows script finished"
