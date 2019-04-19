# #############################################################################
# POWERSHELL
# NAME: restart_ClaimsDocMgmtSharingWindowsService.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/19/19
# 
# COMMENT:  This script will restart the specified service. To be used in conjunction with 2 scheduled tasks for a 12 hour restart recurrence
#
# TO ADD
# -maybe some cleanup of the log file after x days?
# #############################################################################

# #############################################################################
#functions
# #############################################################################

#begin transcript
$scriptfullname = $MyInvocation.MyCommand.Definition
$scriptnameless = $scriptfullname -replace ".{4}$"
$ScriptDir = (Split-Path $MyInvocation.MyCommand.Path) + "\"
Start-transcript -path $scriptnameless'_logfile.txt' -append

$ServiceName = 'ClaimsDocMgmtSharingWindowsService'
$arrService = Get-Service -Name $ServiceName

try{
Restart-Service -name $ServiceName -Force -Verbose
}
Catch{
    write-host "something went wrong"
}
Finally{
    #lets make sure the service is running before we leave
    if($arrService.Status -ne 'Running'){
        try{
            Start-Service $ServiceName
            if ($arrService.Status -eq 'Running')
            {
            Write-Host "Service $ServiceName is now Running"
            }
        }
        Catch{
            write-host "service $ServiceName could not start"
        }
    }
}


# #############################################################################
# end of script
Stop-transcript