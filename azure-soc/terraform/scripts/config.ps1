[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "TLS CHANGED TO 12"
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force | Out-Null
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging `
                 -Name EnableScriptBlockLogging -Value 1 -Type DWord

Write-Host "ScriptBlockLogging Enabled"
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Force | Out-Null
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging `
                 -Name EnableModuleLogging -Value 1 -Type DWord
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force | Out-Null
New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames `
                 -Name "*" -Value "*" -PropertyType String

New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Force | Out-Null
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription `
                 -Name EnableTranscripting -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription `
                 -Name OutputDirectory -Value "C:\Transcripts"


$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$tempDir = "$env:TEMP\SysmonInstall"
$zipPath = "$tempDir\Sysmon.zip"
$sysmonExe = "$tempDir\Sysmon64.exe"
$configUrl = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$configPath = "$tempDir\sysmonconfig.xml"
Write-Host "Sysmon Installed"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Invoke-WebRequest -Uri $sysmonUrl -OutFile $zipPath
Invoke-WebRequest -Uri $configUrl -OutFile $configPath
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempDir)
Start-Process -FilePath "$sysmonExe" -ArgumentList "-accepteula -i $configPath" -Wait -NoNewWindow



$T = New-JobTrigger -Hourly
Register-ScheduledJob -Name "NewFireWallRule" -ScriptBlock {
  powershell.exe -c 'netsh advfirewall firewall add rule name="Remote Event Log Management SMB" dir=in action=allow protocol=tcp localport=12345'
} -Trigger $T

Write-Host "Scheduled Job Created"


Register-ScheduledJob -Name "Discovery" -ScriptBlock {
  powershell.exe -c "net users ; route print ; arp -a , ping 1.1.1.1 -c 1 ; net view"
} -Trigger $T 
