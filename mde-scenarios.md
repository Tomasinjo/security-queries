
- finding specific software version
https://www.cvedetails.com/vulnerability-list.php?vendor_id=26&product_id=194&version_id=&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=8&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=19&sha=1f5cbc2e2525099939f09a0af572bd5d98193efb
DeviceTvmSoftwareInventory 
| project-keep SoftwareName, SoftwareVendor, SoftwareVersion
//| summarize count() by SoftwareName
| where SoftwareName contains "exchange_server" 



- hunting for password spraying and credential testing
https://thedfirreport.com/2023/01/23/sharefinder-how-threat-actors-discover-file-shares/
DeviceLogonEvents 
| where AccountName !startswith "$"
| where LogonType == "Network"
//| summarize count() by LogonType
| summarize logons_per_user = count_distinct(DeviceName) by AccountName 
| where logons_per_user < 10
| sort by logons_per_user


- unsigned files in appdata
https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
DeviceFileEvents
| where FolderPath contains "appdata"
| where ActionType == "FileCreated"
| where FileName endswith "exe"
| where InitiatingProcessAccountName != "system"
| join DeviceFileCertificateInfo on $left.SHA1 == $right.SHA1
//| where InitiatingProcessFileName !in ( "OneDriveSetup.exe", "DropboxUpdate.exe" )
| where IsTrusted == 0 
| take 50
//| summarize count() by InitiatingProcessFileName, FolderPath


