
$mode = Get-WUServiceManager | Where-Object {$_.IsManaged -eq 'true'} | foreach {$_.ServiceID}

switch ( $mode )
{
	'3da21691-e39d-4da6-8a4b-b43877bcb1b7' { $type = '-WindowsUpdate' }
	'9482f4b4-e343-43b6-b170-9a65bc822c77' { $type = '-WindowsUpdate' }
	'7971f918-a847-4430-9279-4a52d1efe18d' { $type = '-MicrosoftUpdate' }
}

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8';Import-Module PSWindowsUpdate; Get-WUList $type | Format-List -Property Title > C:\ProgramData\os_patching\package_updates
