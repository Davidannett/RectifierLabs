$serverlist = Get-Content C:\temp\svr.txt
ForEach ($server in $serverlist)
{
$resolved = ([system.net.dns]::GetHostByAddress($server)).hostname
$output = $server + " " + $resolved
$output | Add-Content -path C:\temp\servernames.txt
}