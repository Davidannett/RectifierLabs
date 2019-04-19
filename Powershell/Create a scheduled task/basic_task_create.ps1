### this works but still need to figure out the password part as well as "not logged on" portion


$TaskPath = "D:\APPS\service_restarter_task\"
$taskName1 = "restart_ClaimsDocMgmtSharingWindowsService_noon"
$TaskName2 = "restart_ClaimsDocMgmtSharingWindowsService_midnight"
$Trigger1= New-ScheduledTaskTrigger -At 12:00am -Daily
$Trigger2= New-ScheduledTaskTrigger -At 12:00pm -Daily
$User= "ProgHSZQ\ZCLMS24D"
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $TaskPath
Register-ScheduledTask -TaskName $taskName1 -Trigger $Trigger1 -User $User -Action $Action -RunLevel Highest –Force
Register-ScheduledTask -TaskName $taskName2 -Trigger $Trigger2 -User $User -Action $Action -RunLevel Highest –Force






############ developing version

$Trigger1 = New-ScheduledTaskTrigger -At 12:00am -Daily
            $Trigger2 = New-ScheduledTaskTrigger -At 12:00pm -Daily
            $User = "ProgHSZQ\ZCLMS24D"
            $principal = New-ScheduledTaskPrincipal -Userid $user -LogonType S4U -RunLevel Highest
            $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$TaskPath$ScriptName"
            Register-ScheduledTask -TaskName $taskName1 -Trigger $Trigger1 -Action $Action -Force -Principal $principal
            Register-ScheduledTask -TaskName $taskName2 -Trigger $Trigger2 -Action $Action –Force -Principal $principal