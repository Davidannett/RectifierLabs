$configs = get-iisconfigsection -sectionpath "system.webServer/rewrite/allowedServerVariables"
if ($configs.IsLocked -like "False") {
    write-host "Is not locked"
}
else {
    Write-host "is locked"
}