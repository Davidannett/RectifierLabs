$Servers = "SCADSS01" 
$eventID = "6013"
$exportpath = "\\" + $Servers + "\d$\Temp\uptimeevents.csv"

Foreach ($server in $Servers) {

write-host "getting event log data for" $server

get-eventlog  -logname system | where eventid -eq $eventID | select -first 100 | export-csv $exportpath
}
