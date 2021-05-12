##################################################################################################################################
#enable audit log in active directory for gathering information about domain users and their IP address and Their system name.
#Author: Samira Hoseini
###################################################################################################################################


Import-Module GroupPolicy
#Get-Command –Module GroupPolicy
#Read waitTimeafter enabling audit log and log count for get information from input
$waitTime =  Read-Host -Prompt "Input waitTime after enable audit, please"
$logCount =  Read-Host -Prompt  "Input logCount to display, please" 
    
#Enable logon/logoff audit log in active directory 
AuditPol /set /category:"Logon/logoff" /subcategory:"logon" /success:enable /failure:enable
AuditPol /set /category:"Logon/logoff" /subcategory:"other logon/logoff Events" /success:enable /failure:enable
#auditpol.exe /get /category:*

#wait for $waitTime after enable auditing to get log
Start-Sleep -s $waitTime

$computerName= hostname.exe
#filter event log for see only usefull information:(time,accountName,Domain Account,TargetUserName,LogonType=3,IpAddress). exclude system users from list to view only real user information.
#Get-WinEvent -Computer ($computerName) -FilterHashtable @{LogName="Security";ID=4624} | fl
Get-WinEvent  -Computer ($computerName) -FilterHashtable @{LogName="Security";ID=4624} | Select TimeCreated,@{n="AccountName";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "TargetUserName"} |%{$_.'#text'}}},@{n="Domain Account";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "TargetDomainName"}| %{$_.'#text'}}} ,@{n="TargetUserName";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "TargetUserName"} |%{$_.'#text'}}},@{n="LogonType";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "LogonType"} |%{$_.'#text'}}},@{n="IpAddress";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "IpAddress"} |%{$_.'#text'}}}| Where-Object {$_.LogonType -eq '3'} | Where-Object {($_.TargetUserName -Notmatch '.\$')} | Fl | Select-Object -First $logCount | Out-File -FilePath c:\logins.txt

#disable audit log for clean work without footprint.
AuditPol /set /category:"Logon/logoff" /subcategory:"logon" /success:disable /failure:disable
AuditPol /set /category:"Logon/logoff" /subcategory:"other logon/logoff Events" /success:disable /failure:disable
#wait for 10 second and clean eventviewer
Start-Sleep -s 10
Clear-EventLog –LogName Security

