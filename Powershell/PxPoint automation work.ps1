msiexec /i PxPoint-32.msi targetldir="D:\Apps\PxPoint"

$arguments = "/i `"$webDeployInstallerFilePath`" /quiet"




#validate install
If(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match “Pxpoint”}){
    write-host -fore cyan "good"
    }
    Else{
        write-host "bad"
    }

#uninstall existing, this may trigger a reboot!
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match “Pxpoint”} | forEach-Object { $_.Uninstall()}

#install new version
Start-Process msiexec /i PxPoint-32.msi targetldir="D:\Apps\PxPoint"

#7zip extractions
Z:\AppsProd\manual_installation\WO0000002023121>
USPS_NAVTEQ_Install.exe -o"D:\Temp\test" -y

Z:\AppsProd\manual_installation\WO0000002023121>
PARCEL_Install.exe -o"D:\Temp\test" -y

#service management
Set-Service -Name "IISAdmin" -Status stopped
Set-Service -Name "W3SVC" -Status stopped

Set-Service -Name IISAdmin -StartupType Disabled
Set-Service -Name W3SVC -StartupType Disabled

Set-Service -Name IISAdmin -StartupType Automatic
Set-Service -Name W3SVC -StartupType Automatic

Set-Service -Name "IISAdmin" -Status Running -PassThru
Set-Service -Name "W3SVC" -Status Running -PassThru

#Validation
Get-Service IISAdmin | Select-Object Name, StartType, Status
Get-Service W3SVC | Select-Object Name, StartType, Status


If(Get-Service IISAdmin | Where-Object {$_.Status -match “Running”}){
    write-host "running"
}
Else{
    write-host "not running"
}