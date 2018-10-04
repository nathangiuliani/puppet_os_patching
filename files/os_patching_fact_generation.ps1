$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
Import-Module PSWindowsUpdate

Get-WUServiceManager | Where-Object {$_.IsManaged -eq 'true'} | ForEach-Object {

	switch ( $_ )
	{
		'3da21691-e39d-4da6-8a4b-b43877bcb1b7' { Get-WUList | Format-List -Property Title > C:\ProgramData\os_patching\package_updates }
		'9482f4b4-e343-43b6-b170-9a65bc822c77' { Get-WUList -WindowsUpdate | Format-List -Property Title > C:\ProgramData\os_patching\package_updates }
		'7971f918-a847-4430-9279-4a52d1efe18d' { Get-WUList -MicrosoftUpdate | Format-List -Property Title > C:\ProgramData\os_patching\package_updates
		default { Get-WUList | Format-List -Property Title > C:\ProgramData\os_patching\package_updates }
	}
}

