# #############################################################################
# POWERSHELL
# NAME: create scheduled task.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/19/19
# 
# COMMENT:  This script will creat a specified scheduled task(s)
#
# TO ADD
# 
# #############################################################################

# #############################################################################
#functions
function LoadAdminModules
{
    if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1"){
        if (Get-Module -ListAvailable -Name WebAdministration){
            Import-Module WebAdministration -force
        }
    }
        else {
            Add-PSSnapin WebAdministration
        }
}
# #############################################################################

#restarts PS session if not run as administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}"' -f ($myinvocation.MyCommand.Definition))
    exit
    }

#begin transcript
$scriptfullname = $MyInvocation.MyCommand.Definition
$scriptnameless = $scriptfullname -replace ".{4}$"
#$ScriptDir = (Split-Path $MyInvocation.MyCommand.Path) + "\"
Start-transcript -path $scriptnameless'_logfile.txt' -append
#################

$ScriptName = "restart_ClaimsDocMgmtSharingWindowsService.ps1"
$TempPath = "D:\Temp"
$TaskPath = "D:\APPS\service_restarter_task\"
$TaskName1 = "restart_ClaimsDocMgmtSharingWindowsService_5am_EST"
#$TaskName2 = "restart_ClaimsDocMgmtSharingWindowsService_noon"

#add applicable ZID to local admins (otherwise task won't actually work) then test
$localhostname = "$env:COMPUTERNAME"

Switch ($localhostname){
    SCCNSHD1 {$User = "ProgHSZQ\ZCLMS24D"}
    SCCNSHQ1 {$User = "ProgHSZQ\ZCLMS24Q"}
    SCCNSHS1 {$User = "ProgHSZQ\ZCLMS24K"}
    SCCNSHS2 {$User = "ProgHSZQ\ZCLMS24K"}
    SCCNSHP1 {$User = "ProgHSZQ\zclms24p"}
    SCCNSHP2 {$User = "ProgHSZQ\zclms24p"}
    SRCNSHP1 {$User = "ProgHSZQ\zclms24p"}
    SRCNSHP2 {$User = "ProgHSZQ\zclms24p"}
}

write-host "`n"
Write-host -fore cyan -back Black "ZID set to $user based on hostname"
write-host -fore cyan -back Black "now adding $user to local administrators group, if not already there..."

if((Get-LocalGroupMember "Administrators").Name -contains $user){
    write-host "`n"
    Write-Host -fore Cyan "$user properly added to local Administrators group (notice 1)"
}
Else{
Switch ($localhostname){
        SCCNSHD1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24D"}
        SCCNSHD1 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SCCNSHQ1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24Q"}
        SCCNSHQ1 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SCCNSHS1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24k"}
        SCCNSHS1 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SCCNSHS2 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24k"}
        SCCNSHS2 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SCCNSHP1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\zclms24p"}
        SCCNSHP1 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SCCNSHP2 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\zclms24p"}
        SCCNSHP2 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SRCNSHP1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\zclms24p"}
        SRCNSHP1 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
        SRCNSHP2 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\zclms24p"}
        SRCNSHP2 {write-host -fore cyan "ZID $user added to local administrators group per servername "}
    }
}

If((Get-LocalGroupMember "Administrators").Name -contains $user){
    write-host "`n"
    Write-Host -fore Cyan "$user properly added to local Administrators group"
}
else {
    Write-host -fore red -back black "$user is not a member of local administrators! Task will not run!"
}

#create folder for task scheduler files
if(-not (test-path $TaskPath)){
    write-host "`n"
    write-host -fore cyan -back Black "path $taskpath does not exist; creating folder for Task"
    New-Item -ItemType directory -Path $TaskPath
}
if(test-path $TaskPath){
    write-host "`n"
    Write-host -fore Green "Folder for task script exists, copying script"
    Copy-Item -path "$TempPath\$ScriptName" -Destination $TaskPath
    if(test-path "$TempPath\$ScriptName"){
        write-host "`n"
        Write-host -fore Cyan -back Black "Script copied, now creating tasks"
        $Trigger1 = New-ScheduledTaskTrigger -At 5:00am -Daily
        #$Trigger2 = New-ScheduledTaskTrigger -At 12:00pm -Daily
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$TaskPath$ScriptName"
        if(-not (Get-ScheduledTask | Where-Object {($_.TaskName -like $TaskName1)})){
            Write-host -fore cyan -back Black "registering Tasks...."
            Register-ScheduledTask -TaskName $taskName1 -Trigger $Trigger1 -user $user -Action $action -RunLevel Highest
            #Register-ScheduledTask -TaskName $taskName2 -Trigger $Trigger2 -user $user -Action $action -RunLevel Highest
        }
        if(Get-ScheduledTask | Where-Object {$_.TaskName -like $TaskName1 }){
            Write-host -fore cyan "Scheduled Task $taskname1 created successfully"
        }
        Else{
            Write-host -fore red -back Black "Scheduled Task $taskname1 not created"
        }
#        if(Get-ScheduledTask | Where-Object {$_.TaskName -like $TaskName2 }){
#            write-host -fore cyan "Scheduled Task $taskname2 created successfully"
#        }
#        Else{
#            Write-host -fore red -back Black "$taskname2 not created"
#        }
    }
}
    
Else{
    Write-host -fore red "folder creation/existence failed; script aborting"
}

# #############################################################################
# end of script
Write-host -for yellow "script exiting successfully"
Stop-transcript