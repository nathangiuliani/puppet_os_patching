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


[CmdletBinding(defaultparametersetname = "InstallUpdates")]
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

    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Parameter(ParameterSetName = "InstallUpdates")]
    [ValidateScript( {Test-Path -IsValid $_})]
    [String]$ResultFile,

    # timeout
    [Parameter(ParameterSetName = "InstallUpdates-Forcelocal")]
    [Parameter(ParameterSetName = "InstallUpdates-ForceSchedTask")]
    [Parameter(ParameterSetName = "InstallUpdates")]
    [int32]$Timeout,

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
    Write-Host "Running code as a local script block via Invoke-Command"

    Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $scriptBlockParams    
}

Function Invoke-AsScheduledTask {
    [CmdletBinding()]
    param (
        [string]$TaskName = "os_patching job",
        [int32]$WaitMS = 500
    )

    Write-Host "Running code as a scheduled task"

    if (Get-ScheduledJob $TaskName -ErrorAction SilentlyContinue) { 
        Write-Verbose "Removing existing scheduled task first"
        Try {
            Unregister-ScheduledJob $TaskName
        }
        Catch {
            Write-Error "Unable to remove existing scheduled task, is another copy of this script still running?"
        }
    }

    Write-Verbose "Registering scheduled task with a start trigger in 2 seconds time"

    # define scheduled task trigger
    $trigger = @{
        Frequency = "Once" # (or Daily, Weekly, AtStartup, AtLogon)
        At        = $(Get-Date).AddSeconds(2) # in 2 seconds time
    }

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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    # wait up to one mintue for the task to start
    # it can take some time especially on older versions of windows
    while ($psTaskFolder.GetTask($TaskName).State -ne 4 -and $stopWatch.ElapsedMilliseconds -lt 60000) {
        Write-Verbose "Task Status: $($taskStates[$psTaskFolder.GetTask($TaskName).State]) - Waiting another $($WaitMS)ms for scheduled task to start"
        Start-Sleep -Milliseconds $WaitMS
    }

    Write-Verbose "Invoking wait-job to wait for job to finish and get job output."
    Write-Verbose "A long pause here means the job is running and we're waiting for results."

    # wait for scheduled task to finish
    # technically we could get into an endless loop here - but the only way around it is to
    # set some arbitary limit (e.g. 3 hours) for the maximum length of a task run and then forcefully
    # terminate the job, which doesn't seem to be a good idea

    $job = $null
    while ($null -eq $job) {
        try {
            $job = wait-job $TaskName
        }
        catch [System.Management.Automation.PSArgumentException] {
            # wait-job can't see the job yet, this takes some time
            # so wait a bit longer for wait-job to work!
            Write-Verbose "  Waiting another $($WaitMS)ms for wait-job to pick up the job."
            Start-Sleep -Milliseconds $WaitMS
        }
    }

    # rumour has it that it can take a while for the job output to be available
    # even after wait-job has finished. wait for 30 seconds here. Thanks for this
    # idea ansible Windows update module!
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($null -eq $job.Output -and $stopWatch.ElapsedMilliseconds -lt 60000) {
        Write-Verbose "Waiting another $($WaitMS)ms for job output to populate"
        Start-Sleep -Milliseconds $WaitMS
    }

    Write-Host "Deleting scheduled task"

    $running_tasks = @($taskScheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName })
    foreach ($task_to_stop in $running_tasks) {
        Write-Verbose "Task still seems to be running, stopping it before unregistering it"
        $task_to_stop.Stop()
    }

    Unregister-ScheduledJob $TaskName

    # write any verbose output
    Write-Verbose "Verbose output from scheduled task follows, this will not be in sync with any non-verbose output"
    $job.Verbose | Write-Verbose

    # return job output to pipeline
    $job.Output # pipeline

    # return any error output and exit in a controlled fashion
    if ($job.error) {
        Write-Error -ErrorAction Continue "Error returned from scriptblock:"
        $job.Error | Write-Error -ErrorAction Continue
        exit 166
    }
}

# trap
trap {
    # using write-error so error goes to stderr which ruby picks up
    # erroraction continue ensures execution doesn't stop until our controlled exit
    Write-Error -ErrorAction Continue "Unhandled exception caught in main script:"
    Write-Error -ErrorAction Continue $_.exception.ToString()                                          # Error message
    Write-Error -ErrorAction Continue $_.invocationinfo.positionmessage.ToString()                     # Line the error was generated on
    exit 165
}

# main script code is  here!

# Script block for invoke-command (local) or scheduled task

# Note that due to the use of a scheduled job, and allowing for compatibility with older
# versions of windows, we actually can't get the data returned from write-host back. This
# 'information' stream only exists on newer versions of windows or powershell (unsure of
# the specifics). Since we can only get pipeline, verbose, warning and debug output, we
# have our own logging function and call this to capture a nice, clean sequence of events
# which get "returned". The upstream ruby script that calls this to initiate a patching run
# includes this as the 'debug' data in the task result. The code also saves a json file with
# the update results, and outputs this prefixed with '##Output File is'. The ruby script
# finds this and reads the file to get the list of updates and installation status as required.
# There may be nicer ways of doing this - e.g. detecting the invoke type and using native
# write- cmdlets, or detecting the windows version and using the information stream where it
# exists, however this is probably not necessary. The intended use case for this code is from
# the os_patching::patch_servers task, which won't return real-time line-by-line updates anyway
# so having all the output returned after everything is done in this script is really only an
# issue when developing.

# Also note we pass the script block a pscustomobject with all the relevant script parameters.
# This is because the registered job method of passing an ordered sequence of arguments, rather
# than a parameter block is a bit clunky and unreliable. Passing a single argument with parameters
# in a manipulateable block was found to be more consistent and reliable.

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

    # set verbose and debug preference based on parameters passed
    $VerbosePreference = $Params.VerbosePreference
    $DebugPreference = $Params.DebugPreference

    # start with empty array for the log
    # forcing the scope as it's different depending on whether we are using
    # invoke-command or a scheduled job to execute this script block
    $script:log = @()

    # trap
    trap {
        # using write-error so error goes to stderr which ruby picks up
        # erroraction continue ensures execution doesn't stop until our controlled exit
        Write-Error -ErrorAction Continue "Unhandled exception caught in scriptblock:"
        Write-Error -ErrorAction Continue $_.exception.ToString()                                          # Error message
        Write-Error -ErrorAction Continue $_.invocationinfo.positionmessage.ToString()                     # Line the error was generated on
        exit 166
    }

    #
    # functions
    #


    Function Add-LogEntry {
        # function to add a log entry for our script block
        # takes the input and adds to a script-scope log variable, which is intended to
        # be an array
        # inputs - log entry/entries either on pipeline, as a string or array of strings
        # outputs - none
        [CmdletBinding()]
        param (
            [parameter(ValueFromRemainingArguments, Mandatory)]
            [string[]]$logEntry
        )
        begin {}
        process {
            foreach ($entry in $logEntry) {
                $script:log += $logEntry
            }
        }
        end {}
    }
    Function Get-WUSession {
        # returns a microsoft update session object
        Write-Debug "Get-WUSession: Creating update session object"
        New-Object -ComObject 'Microsoft.Update.Session' 
    }

    Function Get-WUUpdateCollection {
        #returns a microsoft update update collection object
        Write-Debug "Get-WUUpdateCollection: Creating update collection object"
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
 
        if ($rebootPending) { Add-LogEntry "A reboot is required" }

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

        Add-LogEntry "Refreshing puppet facts"

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
        Add-LogEntry "Uploading puppet facts"
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

        # create update searcher
        $updateSearcher = $UpdateSession.CreateUpdateSearcher()

        Add-LogEntry "Performing update search with criteria: $($Params.UpdateCriteria)"

        # perform search and select Update property
        $updates = $updateSearcher.Search($Params.UpdateCriteria).Updates

        $updateCount = @($updates).count

        Add-LogEntry "Detected $updateCount updates are required in total (including security)"

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
        # add a filterable categories parameter, then filter only to updates that include the security classification
        $secUpdates = $Updates | Add-Member -MemberType ScriptProperty -Name "CategoriesText" -value {$This.Categories | Select-Object -expandproperty Name} -PassThru | Where-Object {$_.CategoriesText -contains "Security Updates"}
        
        # count them
        if ($secUpdates) {
            $secUpdateCount = @($secUpdates).count

            Add-LogEntry "Detected $secUpdateCount of the required updates are security updates"

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
            Add-LogEntry "Only installing updates that include the security update classification"
            $updatesToInstall = Get-SecurityUpdates -Updates $allUpdates
        }
        else {
            $updatesToInstall = $allUpdates
        }

        if ($Params.OnlyXUpdates -gt 0) {
            Add-LogEntry "Selecting only the first $($Params.OnlyXUpdates) updates"
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
            Add-LogEntry "No updates required, no action taken"

            # return null
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

            Add-LogEntry "Downloading $(@($updateDownloadCollection).Count) updates that are not cached locally"

            # Create update downloader
            $updateDownloader = $updateSession.CreateUpdateDownloader()

            # Set updates to download
            $updateDownloader.Updates = $updateDownloadCollection

            # and download 'em!
            [void]$updateDownloader.Download()
        }
        else {
            Add-LogEntry "All updates are already downloaded"
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

        Add-LogEntry "Installing $updateCount updates"

        # create a counter var starting at 1
        $counter = 1

        # create blank array for result output
        $updateInstallResults = @()

        # create update collection object
        $updateInstallCollection = Get-WUUpdateCollection

        # create update installer object
        $updateInstaller = $updateSession.CreateUpdateInstaller()

        foreach ($update in $updatesToInstall) {

            # check if we have time to install updates, e.g. at least 5 minutes left
            #
            # TODO: Be a bit smarter here, perhaps use SCCM's method of estimating 5 minutes
            # per update and 30 minutes per cumulative update?
            #
            if ([datetime]::now -gt $endTime.AddMinutes(-5)) {
                Add-LogEntry "Skipping remaining updates due to insufficient time"
                Break
            }

            Add-LogEntry "Installing update $($counter)/$(@($updatesToInstall).Count): $($update.Title)"

            # clear update collection...
            $updateInstallCollection.Clear()

            # ...Add the current update to it
            [void]$updateInstallCollection.Add($update) # void stops output to console

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
        # return results
        $updateInstallResults
    }

    Add-LogEntry "os_patching_windows scriptblock started"

    #create update session
    $wuSession = Get-WUSession

    if ($Params.RefreshFacts) {
        # refresh facts mode
        Invoke-RefreshPuppetFacts -UpdateSession $wuSession
    }
    else {
        # first, calculate end time based on timeout parameter if it's been provided
        if ($null -ne $Params.Timeout -and $Params.Timeout -ge 1) {
            $endTime = [datetime]::now.AddSeconds($Params.Timeout)
            Add-LogEntry "Timeout of $($Params.Timeout) seconds provided. Calculated target end time of update installation window as $endTime"
        }
        else {
            $endTime = $null
            Add-LogEntry "No timeout value provided, script will run until all updates are installed"
        }

        # invoke update run, convert results to CSV and send down the pipeline
        $updateRunResults = Invoke-UpdateRun -UpdateSession $wuSession

        # calculate filename for results file
        $outputFileName = "os_patching_results_{0:yyyy-MM-dd-HH-mm}.json" -f (Get-Date)
        $outputFilePath = Join-Path -Path $env:temp -ChildPath $outputFileName

        # output as JSON with ASCII encoding which plays nice with puppet etc
        $updateRunResults | ConvertTo-Json | Out-File $outputFilePath -Encoding ascii

        # we want this one in the pipeline no matter what, so that it's returned as output
        # from the scheduled task method
        Add-LogEntry "##Output File is $outputFilePath"
    }

    Add-LogEntry "os_patching_windows scriptblock finished"

    # return log
    $script:log
}

# main code
Write-Host "os_patching_windows script started"

#build parameter PSCustomObject for passing to the scriptblock
$scriptBlockParams = [PSCustomObject]@{
    RefreshFacts      = $RefreshFacts 
    SecurityOnly      = $SecurityOnly    
    UpdateCriteria    = $UpdateCriteria    
    OnlyXUpdates      = $OnlyXUpdates
    Timeout           = $Timeout
    DebugPreference   = $DebugPreference
    VerbosePreference = $VerbosePreference
}

Write-Verbose "Trying to access the windows update API locally..."

try {
    # try to create a windows update downloader
    (New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownloader() | Out-Null
    $localSession = $true
    Write-Verbose "Accessing the windows update API locally succeeded"
}
catch [System.Management.Automation.MethodInvocationException],[System.UnauthorizedAccessException] {
    # first exception type seems to be thrown in earlier versions of windows
    # second in the later (e.g. 2016)
    $localSession = $false
    Write-Verbose "Accessing the windows update API locally failed"
}

# run either in an invoke-command or a scheduled task based on the result above and provided command line parameters
# refresh facts is always in an invoke-command as the update search API works in a remote session
if ((($localSession -or $ForceLocal) -and -not $ForceSchedTask) -or $RefreshFacts) {
    if ($ForceLocal) { Write-Warning "Forced running locally, this may fail if in a remote session" }
    Invoke-AsCommand
}
else {
    if ($ForceSchedTask) { Write-Warning "Forced running in a scheduled task, this may not be necessary if running in a local session" }
    Invoke-AsScheduledTask
}

Write-Host "os_patching_windows script finished"
