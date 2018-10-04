#!/opt/puppetlabs/puppet/bin/ruby
require 'open3'
require 'json'
require 'win32/registry'

params = JSON.parse(STDIN.read)

begin
  allow_reboot = if params['reboot'] == false
                   '-IgnoreReboot'
                 else
                   ''
                 end
  # Find if we are using WSUS or Windows Update
  manager_cmd = "powershell -command \"Import-Module PSWindowsUpdate; Get-WUServiceManager | Where-Object {$_.IsManaged -eq 'true'} | foreach {$_.ServiceID}\""
  stdout, stderr, status = Open3.capture3(manager_cmd)
  raise 'Cannot get Windows Update configurations', stderr if status != 0
  # Determine which service is enable can use that to apply patches and updates
  if stdout
    case stdout.strip
    when '3da21691-e39d-4da6-8a4b-b43877bcb1b7'
      cmd_string = "powershell -command \"Import-Module PSWindowsUpdate; Get-WUInstall -AcceptAll #{allow_reboot}\""
    when '9482f4b4-e343-43b6-b170-9a65bc822c77'
      cmd_string = "powershell -command \"Import-Module PSWindowsUpdate; Get-WUInstall -WindowsUpdate -AcceptAll #{allow_reboot}\""
    when '7971f918-a847-4430-9279-4a52d1efe18d'
      cmd_string = "powershell -command \"Import-Module PSWindowsUpdate; Get-WUInstall -MicrosoftUpdate -AcceptAll #{allow_reboot}\""
    else
      puts 'No Update Services configured'
      exit 0
    end
    # run the relevant command
    stdout, _stderr, status = Open3.capture3(cmd_string)
    if status.zero?
      puts stdout.strip
    	_fact_out, _stderr, _status = Open3.capture3('powershell C:/ProgramData/os_patching/os_patching_fact_generation.ps1')
      exit 0
    else
      puts 'Could not apply patch'
    	_fact_out, _stderr, _status = Open3.capture3('powershell C:/ProgramData/os_patching/os_patching_fact_generation.ps1')
      exit 1
    end
  end
rescue StandardError => e
  raise "There was a problem #{e.message}"
end
