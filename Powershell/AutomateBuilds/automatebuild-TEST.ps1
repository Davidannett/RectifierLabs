<#
.SYNOPSIS
ASPS written engine to automate common post-factory build steps
##
.DESCRIPTION
TBD
	
.PARAMETER ActionsFile
Path to the XML file specifying all actions

.PARAMETER WhatIf
(Optional) Switch to not affect any changes to the target server (i.e. only generate log output and check for logic errors)

.PARAMETER Passwords
(Optional) Passwords to use during install, formatted as 'Account=Password','Account=Password','Account=Password' (e.g. -Passwords 'PROG1\ZMYAPP01D=P&ssw0rd','PROG1\ZMYAPP02D=p&$$wOrd')

.PARAMETER ComputerName
(Optional) Overriding computer name to use for configuration steps (usually used with -WhatIf)

.PARAMETER Facts
(Optional) Overriding (or setting) calculated "facts" about the configuration.
Usage: -Facts 'Environment=Development','Location=Cloud','Slot=Alpha'

.PARAMETER Domain
(Optional) overriding the domain of the current server (e.g. for testing purposes)

.PARAMETER LogVerbose
(Optional) Switch to include more extensive logging

.PARAMETER LogFolder
(Optional) overriding the log folder (defaults to D:\Data\Logs\ASPS.AutomateBuild)

.PARAMETER OnError
(Optional) Values: "Abort" to have the script summarily stop; "Continue" (default) to have the script continue attempting more actions; "Pause" to prompt for user interaction to continue

.PARAMETER StepThrough
(Optional) Pause for confirmation of execution before each valid action

.PARAMETER SpecificIDs
(Optional) List of specific IDs to execute (e.g. -SpecificIDs 'Pool:AppPool1','Site:MyNewSite')

.PARAMETER Quiet
(Optional) Switch to suppress command window output

.PARAMETER RemoteComputers
(Optional) Remote computers to run the build engine against
Usage: -RemoteComputers ServerA,ServerB,ServerC

.PARAMETER ActionsHash
(Internal Use) Used to leave breadcrumbs for actions file version on servers during execution

.PARAMTER EngineHash
(Internal Use) Used to leave breadcrubms for engine version on servers during execution

.PARAMETER LogKey
(Internal Use) Used to specify how the log should be named on server during remote execution

.NOTES
Name: ASPS.AutomateBuild
Author: William C Thompson
Version: 1.0
DateUpdated: 2016-03-26

.EXAMPLE
.\ASPS.AutomateBuild.ps1 -ActionsFile .\MyProfile.AutomateBuild.xml
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml

Description:
Most typical execution of an XML.  Note the -ActionsFile is positional (required to be the FIRST parameter) making the "-ActionsFile" specification optional.  Can be used in combination with other parameters described in examples.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -WhatIf

Description:
Illustrates using the -WhatIf switch to simulate execution of the script, *only* logging to the window instead of actually making changes.  Can be used in combination with other parameters described in examples.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -WhatIf -ComputerName SCXYZD01 -Domain PROGHSZQ

Description:
Illustrates using -ComputerName to simulate execution as if it were running on a particular server (e.g. SCXYZD01) which is on a specific domain (e.g. PROGHSZQ).  The most typical case for this combination is simulating execution of the script locally for a specific server (to help you test syntax, etc).  Can be used in combination with other parameters described in examples.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -Passwords 'PROG1\ZAPP001D=xyz$123$','PROG1\ZAPP002D=abc#456#'

Description:
Illustrates using -Passwords to supply passwords for Z IDs to the engine to skip prompting.  Can be used in combination with other parameters described in examples.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -Facts 'Environment=Development','InstallSwagger=yes'

Description:
Illustrates using -Facts to override the assignment of those fact names (e.g. Environment, InstallSwagger) of using the FactDefinition nodes in the XML.  Can be used in combination with other parameters described in examples.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -StepThrough

Description:
Executes the engine on the XML and prompts for user confirmation of executing that action before proceeding.  This is useful for initial debugging.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -OnError Pause

Description:
Executes the engine on the XML and pauses if any action failed.  This is useful for initial debugging.

.EXAMPLE
.\ASPS.AutomateBuild.ps1 .\MyProfile.AutomateBuild.xml -SpecificIDs 'Pool:MyAppPool','Site:MyNewSite'

Description:
Executes the engine on the XML but only the actions with IDs of Pool:MyAppPool and Site:MyNewSite.  This is useful for initial debugging.

#>

#region Parameters
# parameters Actions, LogFolder, Domain
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
    [string]$ActionsFile,
    [Parameter(Mandatory=$False)]
    [string]$ComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory=$False)]
    [string[]] $Facts=@(),
    [ValidateSet("PROG1", "PROGHSZQ", "PROGHSZ", "PROGDMZQ", "PROGDMZ", "PROGPKID", "PROGPKIQ", "PROGPKIP", ignorecase=$false)]
    [string]$Domain = (Get-ChildItem Env:USERDOMAIN).Value,
    [Parameter(Mandatory=$False)]
    [string]$LogFolder = "",
    [Parameter()]
    [switch]$LogVerbose = $false,
    [Parameter()]
    [switch]$WhatIf = $false,
    [Parameter()]
    [switch]$StepThrough = $false,
    [Parameter()]
    [string[]]$SpecificIDs = @(),
    [ValidateSet("Abort", "Pause", "Continue", ignorecase=$true)]
    [string]$OnError = "Continue",
    [Parameter()]
    [switch]$Quiet = $false,
    [Parameter()]
    [string[]]$Passwords = @(),
    [Parameter()]
    [string[]]$RemoteComputers = @(),
    [Parameter()]
    [string]$ActionsHash = $(if([bool](Get-Command Get-FileHash -ErrorAction SilentlyContinue)) { $(Get-FileHash $ActionsFile -Algorithm sha1).Hash } else { "MicrosoftDidntThinkHashingShouldBeEasyUntil2008R2" }),
    [Parameter()]
    [string]$EngineHash = $(if([bool](Get-Command Get-FileHash -ErrorAction SilentlyContinue)) { $(Get-FileHash $MyInvocation.MyCommand.Definition -Algorithm sha1).Hash } else { "MicrosoftDidntThinkHashingShouldBeEasyUntil2008R2" }),
    [Parameter()]
    [string]$LogKey = "-1"
)

set-variable -Name XML_VERSION -Value 1 -Option Constant

set-variable -Name EXIT_SUCCESS -Value 0 -Option Constant
set-variable -Name EXIT_INVALID_XML -Value 1 -Option Constant
set-variable -Name EXIT_INVALID_ACTION -Value 2 -Option Constant
set-variable -Name EXIT_INVALID_PARAMS -Value 3 -Option Constant
set-variable -Name EXIT_ACTION_FAILED -Value 4 -Option Constant
set-variable -Name EXIT_DUPLICATE_ID -Value 5 -Option Constant
set-variable -Name EXIT_USER_TERMINATED -Value 6 -Option Constant
set-variable -Name EXIT_MISSING_INPUT -Value 7 -Option Constant
set-variable -Name KEY_LOCATION -Value "HKLM:\Software\Progressive\AutomateBuildEngine" -Option Constant

set-variable -Name CRLF -Value `r`n -Option Constant
#endregion


#region Function definitions
function AbortWithError {
    param ($exitcode, $message, $tip = $null)

    $error = "$($CRLF)FATAL ERROR: $message"
    if(-not $Quiet) {
        $error
        if($tip -ne $null) { "$($CRLF)*** TIPS: $tip" }
    }
    if($logFile.Length -gt 0) {
        $error >> $logFile
        if($tip -ne $null) { "$($CRLF)*** TIPS: $tip" >> $logFile }
    }

    Exit $exitcode
}

function Log {
    param ($message)
    if(-not $Quiet) { $message }
    if($logFile.Length -gt 0) { $message >> $logFile }
}

function LogConsoleOnly {
    param ($message)
    if(-not $Quiet) { $message }
}

function LogWarning {
    param ($message)
    $warning = "WARNING: $message"
    if(-not $Quiet) { $warning }
    if($logFile.Length -gt 0) { $warning >> $logFile }
}

function LogError {
    param ($message)
    $error = "ERROR: $message"
    if(-not $Quiet) { $error }
    if($logFile.Length -gt 0) { $error >> $logFile }
}

function LogVerbose {
    param ($message)

    if($logVerbose) {
        if(-not $Quiet) { ">>> $message" }
        if($logFile.Length -gt 0) { ">>> $message" >> $logFile }
    }
}

function PSModuleAvailable {
    param ($module)
    ($whatIf.IsPresent -or ($module -iin $PSModules))
}

function PSCmdletAvailable {
    param ($cmdlet)
    (Get-Command $cmdlet -ErrorAction SilentlyContinue) -ne $null
}

function Validvalue {
    param (
        $value,
        $validValues
    )

    # case insensitive enumeration
    if($validValues[0] -eq "[ENUM]") {
        $validValues[1..100] -icontains $value
    }
    # case sensitive enumeration
    elseif($validValues[0] -eq "[CENUM]") {
        $validValues[1..100] -contains $value
    }
    # boolean
    elseif($validValues[0] -eq "[BOOL]") {
        @("false","true") -icontains $value
    }
    # boolean or blank
    elseif($validValues[0] -eq "[BOOLB]") {
        @("false","true","") -icontains $value
    }
    # regex expression
    elseif($validValues[0] -eq "[REGEX]") {
        $value -imatch $validValues[1]
    }
    # regex expression or blank
    elseif($validValues[0] -eq "[REGEXB]") {
        ($value -imatch $validValues[1]) -or ($value -eq "")
    }
    else {
        $true
    }
}

function Tokenize {
    param (
        $value
    )

    # replace token names with data the script knows and can stamp into the value
    $returnValue = $value
    if($returnValue -is [String]) {
        foreach($factKey in $serverFacts.Keys) { $returnValue = $returnValue -replace "##$factkey##",$serverFacts[$factKey.ToUpper()] }
        $returnValue = $returnValue -replace "##SERVER##",$ComputerName
        $returnValue = $returnValue -replace "##COMPUTERNAME##",$ComputerName
        $returnValue = $returnValue -replace "##DOMAIN##",$domain
        $returnValue = $returnValue -replace "##IPADDRESS##",$IPAddress
        $returnValue = $returnValue -replace "##SERVERLAST4DIGITS##",$ComputerName.Substring(4)
        $returnValue = $returnValue -replace "##SERVERLAST3DIGITS##",$ComputerName.Substring(5)
        $returnValue = $returnValue -replace "##SERVERLAST2DIGITS##",$ComputerName.Substring(6)
        $returnValue = $returnValue -replace "##SERVERLAST1DIGITS##",$ComputerName.Substring(7)
		$returnValue = $returnValue -replace "##SCRIPTROOT##",$PSScriptRoot

        # replace all references of ##PWD:...## with the actual password
        while ($returnValue -match "##PWD:.*##") {
            $regEx = [regex]'##PWD:.*##'
            $userName = $regEx.Match($returnValue).Value
            $userName = $userName.Replace("##PWD:", "")
            $userName = $userName.Replace("##", "")
            $password = GetPassword $cachedPasswords $userName $false
            $returnValue = $returnValue -replace "##PWD:.*##",$password
        }
    }

    $returnValue
}

function GetActionParam {
    param (
        $actionNode,
        $paramName,
        $mandatory = $True,
        $defaultValue = $null,
        $validValues = $null
    )

    # find all Params meeting the name
    $allParams = $actionNode.SelectNodes("Param[@Name = '$paramName']")

    # copy those applying to the conditions
    $params = @()
    foreach($param in $allParams) {
        $paramConditions = ""
        if ($param.HasAttribute("Conditions")) {
            $paramConditions = $param.attributes['Conditions'].value
        }
        if(FactsMeetConditions $paramConditions) {
            $params += [array]$param
        }
    }

    # make sure there is at least one
    if ($params.Count -eq 0) {
        if($mandatory) {
            $error = "No $paramName Param value selected$CRLF$CRLF$($actionNode.outerXML)"
            AbortWithError $EXIT_INVALID_PARAMS $error "The '$paramName' Param needs to appear exactly once for Action $($actionNode.attributes['Type'].value) (and does not appear at all).  Ensure you have included a value for Param '$paramName'.  Check the Condition attributes on your Param nodes against the values of the facts selected (values shown at the top of the log output)."
        }
        else {
            Tokenize $defaultValue
        }
    }
    # make sure there isn't MORE than 1
    elseif ($params.Count -gt 1) {
        $error = "More than one $paramName Param value selected$CRLF$CRLF$($actionNode.outerXML)"
        AbortWithError $EXIT_INVALID_PARAMS $error "Exactly one '$paramName' Param needs to be selected for Action $($actionNode.attributes['Type'].value) (and $($params.Count) was/were selected).  Check the Condition attributes on your Param nodes against the values of the facts selected (values shown at the top of the log output)."
    }
    # otherwise return the contents!
    else {
        $paramValue = Tokenize $params[0].InnerText.Trim()
        if(-not ($validValues -eq $null)) {
            if(-not (ValidValue $paramValue $validValues)) {
                $error = "Invalid $paramName Param value:$paramValue$CRLF$CRLF$($actionNode.outerXML)"
                AbortWithError $EXIT_INVALID_PARAMS $error "Values for Action $($actionNode.attributes['Type'].value) '$paramName' Param need to follow specific rules which the value selected '$paramValue' does not meet.  Double check the value coded for that param against relevant documentation or examples for this action type.  If you are referencing the value of a ""fact"" (e.g. ##MYFACT##) check the top of the log output to ensure the right fact value was selected."
            }
        }
        $paramValue
    }
}

function GetActionParams {
    param (
        $actionNode,
        $paramName,
        $mandatory,
        $validValues = $null
    )

    # find all Params meeting the name
    $allParams = $actionNode.SelectNodes("Param[@Name = '$paramName']")

    # copy those applying to the conditions
    $params = @()
    foreach($param in $allParams) {
        $paramConditions = ""
        if ($param.HasAttribute("Conditions")) {
            $paramConditions = $param.attributes['Conditions'].value
        }
        if(FactsMeetConditions $paramConditions) {
            $params += [array]$param
        }
    }

    # if it's empty and mandatory, that's an error
    if (($params.Count -eq 0) -and ($mandatory)) {
        $error = "No $paramName Param values selected$CRLF$CRLF$($actionNode.outerXML)"
        AbortWithError $EXIT_INVALID_PARAMS $error "The '$paramName' Param needs to appear at least once for Action $($actionNode.attributes['Type'].value) (and does not appear at all).  Ensure you have included a value for Param '$paramName'.  Check the Condition attributes on your Param nodes against the values of the facts selected (values shown at the top of the log output)."
        @()
    }
    # otherwise return the list
    else {
        foreach ($param in $params) {
            $paramValue = Tokenize $param.InnerText.Trim()
            if(-not ($validValues -eq $null)) {
                if(-not (ValidValue $paramValue $validValues)) {
                    $error = "Invalid $paramName Param value:$paramValue$CRLF$CRLF$($actionNode.outerXML)"
                    AbortWithError $EXIT_INVALID_PARAMS $error "Values for Action $($actionNode.attributes['Type'].value) '$paramName' Param need to follow specific rules which the value selected '$paramValue' does not meet.  Double check the value coded for that param against relevant documentation or examples for this action type.  If you are referencing the value of a ""fact"" (e.g. ##MYFACT##) check the top of the log output to ensure the right fact value was selected."
                }
            }
            $paramList += [array]$paramValue
        }
        $paramList
    }
}

function ValidateParamNames {
    param (
        $actionNode,
        [string[]] $validNames
    )

    $names = $actionNode.SelectNodes("Param/@Name")
    foreach($name in $names) {
        if($validNames.IndexOf($name.Value) -lt 0) {
            $error = "Invalid Param Name $($name.Value)$CRLF$CRLF$($actionNode.outerXML)"
            AbortWithError $EXIT_INVALID_PARAMS $error "The Param Name values for Action $($actionNode.attributes['Type'].value) must be one of the following: $(([string]$validNames).Replace(' ',', ')).  Double check the spelling of the Name value used in <Param Name=""$($name.Value)"" ...>."
        }
    }
}

function GetPassword {
    param (
        $cache,  # hash table of passwords
        $account, # format DOMAIN\ACCOUNT or simply ACCOUNT for current domain
        $normalize = $true
    )

    # normalize account to DOMAIN\NAME
    if($normalize) {
        if(($slashIndex = $account.IndexOf('\')) -lt 0) { $accountDomain = (Get-ChildItem Env:USERDOMAIN).Value }
        else { $accountDomain = $account.SubString(0, $slashIndex) }
        $accountName = $account.SubString($slashIndex + 1)
        $account = "$accountDomain\$accountName".ToUpper()
    }

    # do we have a cached value already? if so, return it
    if($cache.Contains($account)) {
        $lastPassword = $cache[$account]
    }
    else {
        if(-not $Quiet) {
            $lastPassword = Read-Host "Enter password for $account"
            # cache it for next time
            $cache.Add($account, $lastPassword)
        }
        else {
            # we have to abort...
            AbortWithError $EXIT_MISSING_INPUT "Quiet mode unable to prompt for password for $account" "Include -Passwords '$account=xxxxx' in the command line."
        }
    }

    $lastPassword
}

function MaskPasswords {
    param (
        $text
    )

    # make a copy of the text to mask and replace any value from the passwords with ******* and return that
    $maskedText = $text
    $cachedPasswords.Keys | % { $maskedText = $maskedText.Replace($($cachedPasswords[$_]), "*" * $cachedPasswords[$_].Length) }
    $maskedText
}

function HiveDrive {
    param (
        $hive
    )
    $hDrive = $hive.ToUpper()
    if($hDrive -in @("HKLM", "HKCU", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER")){
        $hDrive = (@{"HKLM"="HKLM:\"; "HKEY_LOCAL_MACHINE"="HKLM:\"; "HKCU"="HKCU:\"; "HKEY_CURRENT_USER"="HKCU:\"})[$hDrive]
    }
    $hDrive
}

function KeyValuePairs {
    # parses Key1=Value1;Key2=Value2;Key3=Value into a dictionary
    # e.g. $values = KeyValuePairs("Key1=Value1;Key2=Value2;Key3=Value", ";", "=")
    param (
        $textToParse,
        $delimiter1,
        $delimiter2,
        $validKeys = $null
    )

    $pairs = @{}
    foreach($pair in $textToParse.Split($delimiter1)) {
        # ignore empty key-value pairs
        if($pair.Trim() -ne "") {
            $NameValue = $pair.Split($delimiter2)
            if($NameValue.Length -eq 2) {
                if($validKeys -ne $null) {
                    if(-not ($validKeys.Split(",") -icontains $NameValue[0].Trim())) {
                        throw "Invalid key value '$($NameValue[0].Trim())' in '$textToParse':: Format must be Key1$($delimiter2)Value1$($delimiter1)Key2$($delimiter2)Value2$($delimiter1)Key3$($delimiter2)Value3... and allowed keys are $validKeys"
                    }
                }
                $pairs.Add($NameValue[0].Trim(), $NameValue[1].Trim())
            }
            else {
                throw "Invalid format of '$pair' in '$textToParse':: Format must be Key1$($delimiter2)Value1$($delimiter1)Key2$($delimiter2)Value2$($delimiter1)Key3$($delimiter2)Value3:: and allowed keys are $validKeys..."
            }
        }
    }

    $pairs
}

function GetKeyValue {
    param (
        $keyValuePairs,
        $key,
        $default = $null,
        $caseSensitive = $false
    )

    $keyValue = $default
    if($caseSensitive) {
        if($keyValuePairs.ContainsKey($key)) { $keyValue = $keyValuePairs[$key] }
    }
    else {
        foreach($possibleKey in $keyValuePairs.Keys) {
            if($key -ieq $possibleKey) { $keyValue = $keyValuePairs[$possibleKey] }
        }
    }

    $keyValue
}

function FactsMeetConditions {
    param (
        $conditions
    )

    $allKeysMatch = $true

    # null/empty conditions default to matching
    if($conditions -ne "" -and $conditions -ne $null) {
        $conditionKeyValuePairs = KeyValuePairs $conditions ";" "="

        # check each of the fact names referenced in conditions
        foreach($conditionKey in $conditionKeyValuePairs.Keys) {
            $conditionKeyMatches = $false

            # do we have that fact?
            if($serverFacts.Keys -icontains $conditionKey) {
                foreach($conditionValue in $conditionKeyValuePairs[$conditionKey].Split(",")) {
                    # key matches if it already does or this one does
                    $conditionKeyMatches = $conditionKeyMatches -or ($serverFacts[$conditionKey.ToUpper()] -ieq $conditionValue.Trim())
                }
            }

            # all keys match if they already do AND this one does
            $allKeysMatch = $allKeysMatch -and $conditionKeyMatches
        }
    }

    $allKeysMatch
}

function RegistryKey.Value {
    param ([string]$registryKey, [string]$name, [string]$value)
    Try {
        Get-ItemProperty -Path "$registryKey" | Select-Object -ExpandProperty "$name" -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path "$registryKey" -Name "$name" -Value "$value" -Force | Out-Null
    } catch {
        New-ItemProperty -Path "$registryKey" -Name "$name" -Value "$value" | Out-Null
    }
}

function Service.StatusChange {
    param ([string]$action, [string]$name)
    if ($action -eq "Start")   {$action = Start-Service -Name "$name" | Out-Null}
    if ($action -eq "Stop")    {$action = Stop-Service -Name "$name" | Out-Null}
    if ($action -eq "Restart") {$action = Restart-Service -Name "$name" | Out-Null}
    if(($service = Get-Service -Name "$name") -eq $null) {
        LogError "Error service $name; Service does not exist"
        $actionSuccess = $False
    }
    else {
        $action
        Log "SUCCESS: Service $name"
    }
}
#endregion

# set ALL errors to throw an exception
$ErrorActionPreference = "Stop"

#region logfile
# create the log file, override folder with tenp path if it doesn't exist
$scriptName = $MyInvocation.MyCommand.Name.Replace(".ps1", "")
if($logFolder -eq "") {
    if (Test-Path "D:\Data\Logs" -PathType Container) { $logFolder = "D:\Data\Logs\$scriptName" }
    else { $logFolder = "C:\Temp\$scriptName$("_log")" }
}
elseif (-not (Test-Path $logFolder -PathType Container)) { $logFolder = "C:\Temp\$scriptName$("_log")" }
if ($logFolder.EndsWith("\")) { $logFolder.TrimEnd('\') }
# create the log folder if we need to
if (-not (Test-Path $logFolder -PathType Container)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }

# if a logkey has been supplied, use that
# otherwise, form up log file name as computer + actionsxmlfilename + YYYYMMDDHHMM + .log
if($logKey -eq "-1") {
    $logFile = [string]::Concat($logFolder, "\", $ComputerName, ".", $actionsFile.Substring($actionsFile.LastIndexOf('\') + 1).Replace(".xml", ""), ".", (Get-Date -format "yyyyMMddHHmm"))
}
else {
   $logFolder = "D:\Data\Logs\ASPS.AutomateBuild"
   if (-not (Test-Path $logFolder -PathType Container)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }
   $logFile = [string]::Concat($logFolder, "\", $logKey)
}

if($whatIf.IsPresent) {
    $logFile = [string]::Concat($logFile, ".WhatIf.log")
}
else {
    $logFile = [string]::Concat($logFile, ".log")
}
#endregion

# attempt to make a backup copy of the .xml "next to" the .log file
$loggedActionsFile = [string]::Concat($logFile.Substring(0, $logFile.Length-4), ".xml")
Try {
    Copy-Item -Path $actionsFile -Destination $loggedActionsFile -Force
}
Catch {
    # ignore it
}

LogConsoleOnly "Log File = $logFile"
LogConsoleOnly ""

# echo parameters
Log "COMPUTERNAME = $ComputerName"
Log "Current date/time = $(Get-Date -format "yyyy-MM-dd HH:mm")"
#Log "ASPS.AutomateBuild.ps1 Timestamp: $((Get-ChildItem $PSCommandPath).LastWriteTime.ToShortDateString()) $((Get-ChildItem $PSCommandPath).LastWriteTime.ToShortTimeString())"
Log "Parameters:"
if (Test-Path "$actionsFile") { Log "  Actions File = $actionsFile" } else { Log "  Actions File = Raw Content" }
Log "  Domain = $domain"
Log "  WhatIf mode = $($whatIf.IsPresent)"
Log "  Log Folder = $logFolder"
Log "  Log Verbose = $logVerbose"
Log "  Quiet = $Quiet"
Log "  Facts = $Facts"
Log "  OnError = $OnError"
Log "  StepThrough = $StepThrough"
Log "Loading actions file..."

# load the XML into memory
if (Test-Path "$actionsFile") {
    try {
        [xml]$actionsXML = Get-Content $actionsFile
        $actionsFileModified = (Get-ChildItem $actionsFile).LastWriteTime
        Log "Last Modified: $($actionsFileModified.ToShortDateString()) $($actionsFileModified.ToShortTimeString())"
    } catch {
        AbortWithError $EXIT_INVALID_XML "Unable to load actions file $actionsFile" "Double check the spelling of file name.  Make sure the file exists in location specified.  Try fully-qualifying the path to the file.  Verify the file opens as a valid XML file (even using IE)."
    }
}
else {
    Try {
        [xml]$actionsXML = $actionsFile
        Log "ActionsFile passed as raw content"
    }
    Catch {
        AbortWithError $EXIT_INVALID_XML "Unable to load actions file $actionsFile" "Double check the spelling of file name.  Make sure the file exists in location specified.  Try fully-qualifying the path to the file.  Verify the file opens as a valid XML file (even using IE)."
    }
}

# try to load WebAdministration cmdlets
try {
    $osversion =  [Environment]::OSVersion.Version.ToString(2)

    # should we try to load the snap-in?
    if ($osversion -eq "6.0") #Only applies to Windows 2008 and Vista
    {
        Add-PSSnapin -Name WebAdministration -ErrorAction Stop
    }
    # otherwise just try to load the WebAdminstration error and ignore if it fails
    Import-Module -Name WebAdministration -ErrorAction Ignore
}
catch {
}

# try to load ServerManager cmdlets
try { Import-Module -Name ServerManager -ErrorAction Ignore }
catch { }

# hash table of cached passwords
$cachedPasswords = @{}
$actionResults = @{}

$countAttempts = 0
$countSkips = 0
$countSucceeded = 0
$countFailed = 0
$countNotApplicable = 0
$countIgnoredError = 0

# store passwords passed in
foreach($Password in $Passwords) {
	$firstEqualSign = $Password.IndexOf("=")
    if($firstEqualSign -gt 0) {
        # split pair up into account=password
        $account = $password.Substring(0, $firstEqualSign).ToUpper()
		$password = $password.Substring($firstEqualSign+1)

        # cache it if it's not already in the list
        if(-not $cachedPasswords.Contains($account)) {
			Log "Cached password for $account"
            $cachedPasswords.Add($account, $password)
        }
    }
	else {
		Log "Failed to cache one or more passwords - manual entry may be required"
	}
}

$reminderList = @()
$serviceAccountList = @()

# Check if the -Facts parameter is a file
# If it is, delete all comments and then read them into the array
if(($Facts.Length -gt 0) -and $(Test-Path $Facts[0] -PathType Leaf)) {
    $manifestFacts = $($(Get-Content $Facts[0]) | % {
        if( -not $_.StartsWith("#")) {
            if($_ -match "^(.*)(=)(.*)$") {
                $_
            }
            else {
                AbortWithError 1 "Bad configuration in fact configuration file" "Line content `"$_`" is of incorrect format"
            }
            
        }
    })

    #Allow you to pass both a file as the first parameter and then any overrides to THAT file after it
    #Logical heirarchy from lowest to highest precedence is:
    #Facts in the XML -> Facts in the manifest File -> Facts from command line
    for($i = 1; $i -lt $Facts.Length; $i++) {
        for($j = 0; $j -lt $manifestFacts.Length; $j++) {
            if($manifestFacts[$j].StartsWith($Facts[$i].Split('=')[0])) {
                $manifestFacts[$j] = $Facts[$i]
            }
        }
    }

    $Facts = $manifestFacts
}

#We need to follow a different workflow if -RemoteComputers was specified
if($remoteComputers.Count -gt 0 -and -not $whatIf.IsPresent) {
    #Unfortunately need to precopy any files or folders that exist on a UNC share to the host computer
    #And then need to copy these to the remote computer and update the XML
    #Google "Powershell Double Hop Problem" for pages upon pages of explanations of this issue
    $actionsQuery = "//Actions/Action"
    $actions = $actionsXML.SelectNodes($actionsQuery)

    Remove-Item -Path C:\Temp\ASPS.AutomateBuild.ToCopy -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    $remoteComputers | % { Remove-Item -Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy -Recurse -Force -ErrorAction SilentlyContinue | Out-Null }

    $i = 0
    foreach ($action in $actions) {
        $actionType = $action.attributes['Type'].value
        if($actionType -eq "FileIO.Copy" -and $(GetActionParam $action "Source" $True).StartsWith("\\")) {
            LogVerbose "Detected UNC path in a FileIO.Copy command; precopying files/folders to temporary directory"

            ValidateParamNames $action @("Source","Destination","Recurse","Overwrite")
            $source = GetActionParam $action "Source" $True
            LogVerbose "  Source=$source"

            #Copy file from UNC to local C:\Temp\ASPS.AutomateBuild.ToCopy\$i
            LogVerbose "Copy file/folder from UNC $source to local C:\Temp\ASPS.AutomateBuild.ToCopy\$i"
            if(-not $(Test-Path C:\Temp\ASPS.AutomateBuild.ToCopy)) {
                New-Item -ItemType Directory -Path C:\Temp\ASPS.AutomateBuild.ToCopy | Out-Null
            }

            if (-not $(Test-Path C:\Temp\ASPS.AutomateBuild.ToCopy\$i)) {
                New-Item -ItemType Directory -Path C:\Temp\ASPS.AutomateBuild.ToCopy\$i | Out-Null
            }

            Copy-Item -Path $source -Destination C:\Temp\ASPS.AutomateBuild.ToCopy\$i -Recurse -Force | Out-Null

            #Copy the file from local to D:\Temp\ASPS.AutomateBuild.ToCopy\$i on each server
            LogVerbose "Copy file/folder from local C:\Temp\ASPS.AutomateBuild.ToCopy\$i to remote D:\Temp\ASPS.AutomateBuild.ToCopy\$i"
            $remoteComputers | % {
                if(-not $(Test-Path \\$_\D$\Temp)) { New-Item -ItemType Directory -Path \\$_\D$\Temp | Out-Null }
                if(-not $(Test-Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy)) { New-Item -ItemType Directory -Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy  | Out-Null }
                
                Copy-Item -Path C:\Temp\ASPS.AutomateBuild.ToCopy\$i -Destination \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy\$i -Recurse -Force | Out-Null
            }

            #Update the XML so that the source path now reflects the path on the server
            if ($(Test-Path $source -PathType Leaf) -or $source.Contains("*")) {
                $action.SelectNodes("Param[@Name = 'Source']")[0].InnerText = "D:\Temp\ASPS.AutomateBuild.ToCopy\$i\*"
            }
            else {
                $action.SelectNodes("Param[@Name = 'Source']")[0].InnerText = "D:\Temp\ASPS.AutomateBuild.ToCopy\$i"
            }
            

            $i = $i + 1
        }                      
        elseif($actionType -eq "Model3API.AddSwaggerServer20") {
            $remoteComputers | % {
                if(-not $(Test-Path "\\$_\D$\Temp")) { New-Item -ItemType Directory -Path \\$_\D$\Temp | Out-Null }
                if(-not $(Test-Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy)) { New-Item -ItemType Directory -Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy | Out-Null }
                if(-not $(Test-Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy\SwaggerServer20)) { New-Item -ItemType Directory -Path \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy\SwaggerServer20 | Out-Null }
                Copy-Item -Path "\\Prog1\east\AppsDev\ASPS\Environment\SwaggerServer\2.0" -Destination \\$_\D$\Temp\ASPS.AutomateBuild.ToCopy\SwaggerServer20 -Recurse -Force | Out-Null
            }
        }
    }

    #Reach out to each server in parallel and execute the build engine
    Log "Running AutomateBuild on each remote computer"
    $logFileHash = @{}
    foreach($remoteComputer in $remoteComputers) {
        Remove-Job -Name $remoteComputer -ErrorAction SilentlyContinue

        $logFileKey = [string]::Concat("Remote.", $remoteComputer, ".", $(Get-Date -format "yyyyMMddHHmmss"))
        $logFileHash.Add($remoteComputer, $logFileKey)

        $params = @{
            ActionsFile = '$Using:actionsXML.OuterXml'
            Passwords = '$Using:Passwords'
            ActionsHash = '$Using:actionsHash'
            EngineHash = '$Using:engineHash'
            LogKey = '$Using:logFileKey'
            ComputerName = '$Using:remoteComputer'
            Facts = '$Using:Facts'
            LogVerbose = '$Using:LogVerbose'
        }

        $script = [scriptblock]::Create(".{$(Get-Content $MyInvocation.Mycommand.Definition -Raw)} -Quiet $(&{$args} @params)")

        Invoke-Command -ComputerName $remoteComputer -AsJob -JobName $remoteComputer -ScriptBlock $script | Out-Null
    }

    #Wait for all jobs to complete and print the output status
    Log "Waiting for remote jobs to complete..."
    $remoteJobs = @{}
    $remoteComputers | % { $remoteJobs.Add($_, "Running") }
    $numCompleted = 0

    Write-Host "`r$numCompleted of $($remoteJobs.Count) remote jobs completed" -NoNewline
    while($numCompleted -lt $remoteJobs.Count) {
        $remoteComputers | % { $remoteJobs[$_] = $(Get-Job -Name $_).State}

        $numCompleted = 0
        $remoteJobs.Keys | % { if($remoteJobs[$_] -eq "Completed" -Or $remoteJobs[$_] -eq "Failed") { $numCompleted++ } }

        Write-Host "`r$numCompleted of $($remoteJobs.Count) remote jobs completed" -NoNewline
        sleep 1
    }

    Log "`r`nGathering remote job summary"

    $table = New-Object System.Data.DataTable("Results")
    $table.Columns.Add("Server") | Out-Null
    $table.Columns.Add("Job Status") | Out-Null
    $table.Columns.Add("Time Start") | Out-Null
    $table.Columns.Add("Time Finish") | Out-Null
    $table.Columns.Add("ActionsHash") | Out-Null
    $table.Columns.Add("EngineHash") | Out-Null
    $table.Columns.Add("Reported Errors") | Out-Null

    foreach($remoteComputer in $remoteComputers) {
        $results = $(Invoke-Command -ComputerName $remoteComputer -ScriptBlock { 
            $log = $(Get-Content D:\Data\Logs\ASPS.AutomateBuild\$($args[0])*)
            $($log | FindStr "ERROR" | Measure).Count - 1
            $registry = $(Get-ItemProperty -Path $($args[1]))
            $registry.ActionsHash
            $registry.EngineHash
            $registry.StartTime
            $registry.FinishTime
            $($log | FindStr "FATAL" | Measure).Count
        } -ArgumentList $logFileHash[$remoteComputer],$KEY_LOCATION)

        $row = $table.NewRow()
        $row["Server"] = $remoteComputer
        $row["Job Status"] = $remoteJobs[$remoteComputer]
        $row["Time Start"] = $results[3]
        if($results[4] -eq "-1") { $row["Time Finish"] = "ABORT WITH ERROR" } else { $row["Time Finish"] = $results[4] }
        if($results[1] -eq $actionsHash) { $row["ActionsHash"] = "OK"} else { $row["ActionsHash"] = "FAIL" }
        if($results[2] -eq $engineHash) { $row["EngineHash"] = "OK"} else { $row["EngineHash"] = "FAIL" }
        if($results[5] -gt 0) { $row["Reported Errors"] = "FATAL ERROR" } else { $row["Reported Errors"] = $results[0] }
        $table.Rows.Add($row)

    }

    $tableView = New-Object System.Data.DataView($table)
    $tableView.Sort = "Server ASC"
    $table | Format-Table -AutoSize

    $remoteComputers | % { Remove-Job $_ }
}
else {
    #Create a registry entry for engine and actions file information if not operating in WhatIf mode
    if(-not $whatIf.IsPresent) {
        New-Item -Path $KEY_LOCATION -Force -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path $KEY_LOCATION -Name "ActionsHash" -Value $actionsHash -Force -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path $KEY_LOCATION -Name "EngineHash" -Value $engineHash -Force -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path $KEY_LOCATION -Name "StartTime" -Value $(Get-Date -format "yyyy-MM-dd HH:mm:ss") -Force -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path $KEY_LOCATION -Name "FinishTime" -Value "-1" -Force -ErrorAction Ignore | Out-Null
    }

    # import facts from command line
    $serverFacts = @{}
    foreach($Fact in $Facts) {
        $FactKeyValue = $Fact.Split("=")
        if($FactKeyValue.Count -eq 2) {
            $serverFacts.Add($FactKeyValue[0].Trim().ToUpper(), $(Tokenize $FactKeyValue[1].Trim()))
        }
    }

    # load a list of modules if we are actually applying changes
    if($logVerbose) {
        LogVerbose "Available modules:"
        $PSModules = (Get-Module -ListAvailable).Name
        foreach($PSModule in $PSModules) {
            LogVerbose "  $PSModule"
        }
    }

    # what 'facts' have we defined for this server?
    Log "Selecting facts"
    $factDefinitions = $actionsXML.SelectNodes("//FactDefinition")
    foreach($factDefinition in $factDefinitions) {
        # normalize fact name as trimmed upper case
        $factName = $factDefinition.attributes['Name'].value.Trim().ToUpper()
        
        # cannot duplicate fact names
        if(-not ($serverFacts.Keys -icontains $factName)) {
            LogVerbose "Selecting value for fact $factName"
            $factMatchRules = $factDefinition.SelectNodes("MatchRule")

            # must match on a fact value - supply an appropriate "Default" in a MatchTest to override
            $matchFound = $false

            $serverFacts.Add($factName, "")

            foreach($factMatchRule in $factMatchRules) {
                $matchTest = $factMatchRule.attributes['Test'].value
                $matchValue = $factMatchRule.attributes['Value'].value
                $matchResult = $factMatchRule.InnerText.Trim()
                LogVerbose "  Testing match of $($ComputerName.ToUpper()) against $matchTest ""$matchValue"" to choose $factName fact $matchResult"
                $match = $false
                switch ($matchTest) {
                    "Value" {
                        if($ComputerName -ieq $matchValue) { $match = $true }
                    }
                    "RegEx" {
                        if($ComputerName -imatch "^$($matchValue)$") { $match = $true }
                    }
                    "List" {
                        if($matchValue.Split(",") -icontains $ComputerName) { $match = $true }
                    }
                    "Prefix" {
                        if($ComputerName.ToUpper().StartsWith($matchValue)) { $match = $true }
                    }
                    "Suffix" {
                        if($ComputerName.ToUpper().EndsWith($matchValue)) { $match = $true }
                    }
                    "Default" { $match = $true }
                }

                if($match) {
                    $serverFacts[$factName] = $(Tokenize $matchResult)
                    LogVerbose "    Matches $matchTest ""$matchValue"" -> Setting fact $factName to $matchResult"
                    $matchFound = $true
                }
            }
        }
        else {
            $matchFound = $true
        }
        if(-not $matchFound) {
            AbortWithError EXIT_INVALID_XML "No match found for $($ComputerName.ToUpper()) to choose a value for $factName" "Check the MatchRule nodes for <FactDefinition Name=""$factName"">.  If you are using the -ComputerName parameter, check the spelling of value. If you're running this XML locally, consider passing the -ComputerName parameter followed by an example name of a server.  See also using <MatchRule Test=""Default"" Value="""">(some default)</MatchRule> to always supply a value."
        }
        Log "  fact $factName = $($serverFacts[$factName])"
    }

    # read in the actions node
    $actionsQuery = "//Actions/Action"
    LogVerbose "Selecting actions: $actionsQuery"
    $actions = $actionsXML.SelectNodes($actionsQuery)
    foreach ($action in $actions) {
        Log "------------------------------"

        # get the type attribute
        $actionType = $action.attributes['Type'].value
        if ($action.HasAttribute("Comment")) { $actionComment = " (""$($action.attributes['Comment'].value)"")" } else { $actionComment = "" }
        $actionOnError = "Continue"
        if ($action.HasAttribute("OnError")) { $actionOnError = $action.attributes['OnError'].value }
        $actionID = ""
        if ($action.HasAttribute("ID")) { $actionID = $action.attributes['ID'].value }
        $actionsDependentOn = ""
        if ($action.HasAttribute("DependentOn")) { $actionsDependentOn = $action.attributes['DependentOn'].value }
        $actionConditions = ""
        if ($action.HasAttribute("Conditions")) { $actionConditions = $action.attributes['Conditions'].value }
        $actionErrorTip = $null
        if ($action.HasAttribute("ErrorTip")) { $actionErrorTip = $action.attributes['ErrorTip'].value }

        # echo applicable Param nodes
        if ($action.HasAttribute("Conditions")) { $actionConditionsDesc = "; Conditions=$($action.attributes['Conditions'].value)" } else { $actionConditionsDesc = "" }
        if ($action.HasAttribute("OnError")) { $actionOnErrorDesc = "; On Error=$actionOnError" } else { $actionOnErrorDesc = "" }
        if ($action.HasAttribute("ID")) { $actionIDDesc = "; ID=$($action.attributes['ID'].value)" } else { $actionIDDesc = "" }
        if ($action.HasAttribute("DependentOn")) { $actionDependentOnDesc = "; DependentOn=$actionsDependentOn" } else { $actionDependentOnDesc = "" }
        LogVerbose ("Processing Action: $actionType$actionConditionsDesc")

        $params = $action.SelectNodes("Param")
        foreach ($param in $params) {
            if ($param.HasAttribute("Conditions")) { $paramConditions = "; Conditions=$($param.attributes['Conditions'].value)" } else { $paramConditions = "" }
            LogVerbose ("  Param: $($param.attributes['Name'].value) = $($param.InnerText)$paramConditions")
        }
        LogVerbose ("")

        # check for this ID already being executed
        if($actionID -ne "") {
            if($actionResults[$actionID]) {
                AbortWithError EXIT_DUPLICATE_ID "Duplicate ID $actionID in XML" "Search the actions file for '$actionID' to see the duplicate usage."
            }
            # set the action result to ? until it gets attempted and determined what happened
            $actionResults.Add($actionID, "?")      # ? effectively means skipped - it will get set later if we attempt it
        }

        # if the action does not meet the conditions ignore it
        if(-not (FactsMeetConditions $actionConditions)) {
            Log "Conditions [$actionConditions] not met for:: $actionType$actionComment$actionOnErrorDesc$actionIDDescactionDependentOnDesc"
            $countNotApplicable = $countNotApplicable + 1
        }
        else {
    #region ActionTypeSwitch
            Log "Executing:: $actionType$actionComment$actionOnErrorDesc$actionIDDesc$actionDependentOnDesc"

            # check actions it depends on
            $attemptAction = $true
            if($actionsDependentOn -ne "") {
                $checkActions = $actionsDependentOn.Split(",")
                $incrementCount = 0
                foreach($actionDependentOn in $checkActions) {
                    switch ($actionResults[$actionDependentOn]) {
                        # true means it was attempted and succeeded
                        $true {
                            LogVerbose "  Action is dependent on ID $actionDependentOn which succeeded"
                        }
                        # $false means it was attempted and failed
                        $false {
                            Log "  *** Skipping this action because action ID=$actionDependentOn failed"
                            $attemptAction = $false
                            $incrementCount = 1
                        }
                        # ? means it was not attempted because it was skipped due to an upstream dependency
                        "?" {
                            Log "  *** Skipping this action because action ID=$actionDependentOn was also skipped"
                            $attemptAction = $false
                            $incrementCount = 1
                        }
                        # null means it wasn't attempted yet and that's a fatal error
                        $null {
                            Log "  *** Skipping this action because action ID=$actionDependentOn has not been attempted"
                            $attemptAction = $false
                            $countSkips += 1
                            AbortWithError $EXIT_INVALID_XML "Action ID $actionDependentOn has not been defined and is listed as a precondition for this action" "Search the actions file for 'ID=""$actionDependentOn""' and be sure it preceeds this action in the script.  Double check the spelling of the ID for the Action you are attempting to reference against the spelling of the DependentOn value '$actionDependentOn'."
                        }
                    }
                }
                $countSkips += $incrementCount
            }

            # we are about to attempt - do we clear to clear it with the user?
            if($attemptAction -and ($StepThrough -or ($specificIDs.Length -gt 0)) -and (-not $Quiet)) {
                # did we ask on the command line to execute specific instructions (by ID)?
                if($specificIDs.Length -gt 0) {
                    # if the action does not have an ID or it's not in the list, skip it
                    if(($actionID.Length -eq 0) -or ($specificIDs -inotcontains $actionID)) {
                        Log "  *** Skipping this action on user request - treating action as success"
                        $attemptAction = $false
                        $countSkips += 1
                        $actionSuccess = $True
                        $actionResults[$actionID] = $true    # for dependent actions, assume this worked
                    }
                }
                else {
                    $key = Read-Host "Pausing for confirmation: (N)o to skip; Yes to (A)ll; E(x)it script; Anything else to continue"
                    if($key -ieq "n") {
                        Log "  *** Skipping this action on user request - treating action as success"
                        $attemptAction = $false
                        $countSkips += 1
                        $actionSuccess = $True
                        $actionResults[$actionID] = $true    # for dependent actions, assume this worked
                    }
                    elseif($key -ieq "a") {
                        $StepThrough = $false
                    }
                    elseif($key -ieq "x") {
                        $StepThrough = $false
                        Exit $EXIT_USER_TERMINATED
                    }
                }
            }

            if($attemptAction) {
                $countAttempts += 1
                $actionSuccess = $True
                switch ($actionType) {
                    "Log.WriteLogEntry" {
                        ValidateParamNames $action @("Text")
                        $text = GetActionParam $action "Text" $True
                        Log "  Text=$text"
                    }

                    "Log.AddReminder" {
                        ValidateParamNames $action @("Text")
                        $texts = GetActionParams $action "Text" $True
                        foreach($text in $texts) { Log "  Text=$text" }

                        # NOTE: Intentionally not checking -WhatIf so we can test the reminders
                        foreach($text in $texts) {
                            Try {
                                $reminderList += [array]($text)
                                Log "SUCCESS: Added reminder $text"
                            }
                            Catch {
                                LogError ("Unable to add reminder $text")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Prompt.Note" {
                        ValidateParamNames $action @("Text")
                        $text = GetActionParam $action "Text" $False "Enter a note"
                        Log "  Text=$text"

                        Try {
                            if(-not $Quiet) {
                                $note = Read-Host "$text"
                                Log "User Note = $note"
                            }
                        }
                        Catch {
                            LogError ("Unable to prompt the user for a note")
                            Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                            Log ("  Exception Message: $($_.Exception.Message)")
                            $actionSuccess = $False
                        }
                    }

                    "Prompt.Fact" {
                        ValidateParamNames $action @("Name", "Prompt", "AllowOverride")
                        $name = GetActionParam $action "Name" $True
                        $prompt = GetActionParam $action "Prompt" $False "Enter a value for $name"
                        $allowOverride = GetActionParam $action "AllowOverride" $False $null @("[BOOL]")
                        $allowOverride = (($allowOverride -ieq "true") -or ($allowOverride -eq $True))
                        Log "  Name=$name"
                        Log "  Prompt=$prompt"
                        Log "  AllowOverride=$allowOverride"

                        Try {
                            # if we're not allowed to override (or we're in quiet mode) AND the fact is already defined, use the defined fact
                            if(($Quiet -or (-not $allowOverride)) -and ($serverFacts.Keys -icontains $name.Trim())) {
                                Log ("Using value already set for fact $name - See above in output")
                            }
                            # otherwise prompt for it if we're not in Quiet mode
                            elseif(-not $Quiet) {
                                $newValue = (Read-Host "$prompt").Trim()
                                if($serverFacts.Keys -icontains $name.Trim()) {
                                    $serverFacts[$name.Trim().ToUpper()] = $newValue
                                }
                                else {
                                    $serverFacts.Add($name.Trim().ToUpper(), $newValue)
                                }
                            }
                            # otherwise we have to fail
                            else {
                                # the user can control this as DependentOn so we can simply fail the action
                                LogError ("Quiet mode unable to prompt for a fact value for $name.  Include -Facts '$name=xxxxx' in the command line.")
                                $actionSuccess = $False
                            }
                        }
                        Catch {
                            LogError ("Unable to prompt the user for a fact value for $name")
                            Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                            Log ("  Exception Message: $($_.Exception.Message)")
                            $actionSuccess = $False
                        }
                    }

                    "IIS.CreateApplicationPool" {
                        ValidateParamNames $action @("Name","Framework","PipelineMode","IdentityType","UserName","AutoStart","Start","RecycleInterval","RecycleTime","IdleTimeout","Enable32BitAppOnWin64")
                        $name = GetActionParam $action "Name" $True
                        $framework = GetActionParam $action "Framework" $False "v4.0" @("[ENUM]", "v2.0", "v4.0")
                        $pipelineMode = GetActionParam $action "PipelineMode" $False "Integrated" @("[ENUM]", "Integrated", "Classic")
                        $identityType = GetActionParam $action "IdentityType" $False "ApplicationPoolIdentity" @("[ENUM]", "LocalSystem", "LocalService", "NetworkService", "SpecificUser", "ApplicationPoolIdentity")
                        $autoStart = GetActionParam $action "AutoStart" $False "" @("[BOOLB]")
                        $userName = GetActionParam $action "UserName" $False $null @("[REGEX]", "^[A-Za-z0-9]+\\[A-Za-z0-9]+$")
                        $start = GetActionParam $action "Start" $False $True @("[BOOL]")
                        $start = (($start -ieq "true") -or ($start -eq $True))
                        $recycleInterval = GetActionParam $action "RecycleInterval" $False $null @("[REGEXB]", "^[0-9]+$")
                        $recycleTimes = GetActionParams $action "RecycleTime" $False @("[REGEXB]", "^[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$")
                        $idleTimeout = GetActionParam $action "IdleTimeout" $False $null @("[REGEX]", "^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$")
                        $enable32BitAppOnWin64 = GetActionParam $action "Enable32BitAppOnWin64" $False $null @("[BOOLB]")
                        if(($enable32BitAppOnWin64 -ne $null) -and ($enable32BitAppOnWin64 -ne "")) { $enable32BitAppOnWin64 = (($enable32BitAppOnWin64 -ieq "true") -or ($enable32BitAppOnWin64 -eq $True)) }
                        Log "  Name=$name"
                        Log "  Framework=$framework"
                        Log "  PipelineMode=$pipelineMode"
                        Log "  IdentityType=$identityType"
                        Log "  AutoStart=$autoStart"
                        Log "  UserName=$userName"
                        Log "  Start=$start"
                        Log "  RecycleInterval=$recycleInterval"
                        foreach($recycleTime in $recycleTimes) { Log "  RecycleTime=$recycleTime" }
                        Log "  IdleTimeout=$idleTimeout"
                        Log "  Enable32BitAppOnWin64=$enable32BitAppOnWin64"

                        # hash pipelineMode & identityType to their magic constant values
                        $pipelineMode = (@{"Integrated"=0; "Classic"=1})[$pipelineMode]
                        $identityType = (@{"LocalSystem"=0; "LocalService"=1; "NetworkService"=2; "SpecificUser"=3; "ApplicationPoolIdentity"=4})[$identityType]

                        # keep a running list of passwords we need
                        if ($identityType -eq 3) {
                            if(-not ($serviceAccountList -icontains $userName)) { $serviceAccountList += [array]$userName }
                        }

                        if(-not (PSCmdletAvailable "New-WebAppPool")) {
                            LogError "Unable to attempt action; New-WebAppPool cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # create the app pool if it doesn't exist
                                if(-not (Test-Path "IIS:\AppPools\$name")) {
                                    LogVerbose "Creating new app pool $name"
                                    New-WebAppPool -Name $name | Out-Null
                                }

                                LogVerbose "Setting app pool $name managedruntimeversion, managedpipelinemode, processmodel.identitytype to $framework, $pipelineMode, $identityType"
                                $pool = Get-Item "IIS:\AppPools\$name"
                                $pool.managedruntimeversion = "$framework"
                                $pool.managedpipelinemode = $pipelineMode
                                $pool.processmodel.identitytype = $identityType

                                # handle extra stuff for "SpecifcUser"
                                if ($identityType -eq 3) {
                                    LogVerbose "Setting app pool $name username to $userName and (password)"
                                    $password = GetPassword $cachedPasswords $userName
                                    $pool.processModel.userName = $userName
                                    $pool.processModel.password = "$password"
                                }
                                elseif ($identityType -in @(0, 1, 2, 4)) { <# intentionally do nothing #> }

                                $pool | Set-Item

                                # remove autostart property & set if they specified a value
                                Clear-ItemProperty "IIS:\AppPools\$name" -Name autoStart
                                if($autoStart -ne "") {
                                    LogVerbose "Setting app pool $name autoStart to $autoStart"
                                    Set-ItemProperty "IIS:\AppPools\$name" -Name autoStart -Value $autoStart
                                }

                                if($recycleInterval -eq "") {
                                    LogVerbose "Clearing app pool $name recycling.periodicRestart.requests"
                                    Clear-ItemProperty "IIS:\AppPools\$name" -Name recycling.periodicRestart.requests
                                }
                                elseif($recycleInterval -ne $null) {
                                    LogVerbose "Setting app pool $name recycling.periodicRestart.requests to $recycleInterval"
                                    Set-ItemProperty "IIS:\AppPools\$name" -Name recycling.periodicRestart.requests -Value $recycleInterval
                                }

                                if($idleTimeout -eq "") {
                                    LogVerbose "Clearing app pool $name processModel.idleTimeout"
                                    Clear-ItemProperty "IIS:\AppPools\$name" -Name processModel.idleTimeout
                                }
                                elseif($idleTimeout -ne $null) {
                                    LogVerbose "Setting app pool $name processModel.idleTimeout to $idleTimeout"
                                    Set-ItemProperty "IIS:\AppPools\$name" -Name processModel.idleTimeout -Value "$idleTimeout"
                                }

                                if($recycleTimes.Count -gt 0) {
                                    # clear all recycle times
                                    Clear-ItemProperty "IIS:\AppPools\$name" -Name recycling.periodicRestart.schedule

                                    # rebuild list of recycle times
                                    foreach($recycleTime in $recycleTimes) {
                                        # blank means ignore it (i.e. just clear the list)
                                        if($recycleTime -ne "") {
                                            LogVerbose "Adding app pool $name recycling.periodicRestart.schedule value $recycleTime"
                                            New-ItemProperty -Path "IIS:\AppPools\$name" -Name recycling.periodicRestart.schedule -Value @{value=$recycleTime}
                                        }
                                    }
                                }

                                # only set or clear the property if it was specifically defined in the XML
                                <# I'm commenting this out rather than removing it because this was intended to clear the setting
                                   and set it back to the default server value. We may want that behavior at some point. However,
                                   this first conditional is always evaluating to true because of the input sanitation above, so this
                                   breaks the ability to set an AppPool to 64 bit. I think it's better behavior to explicitly state what you want
                                   an action to do, rather than pass a blank value and expect something to happen. -James Brummer 12/6/2017

                                if($enable32BitAppOnWin64 -eq "") {
                                    LogVerbose "Clearing app pool $name enable32BitAppOnWin64"
                                    Clear-ItemProperty "IIS:\AppPools\$name" -Name enable32BitAppOnWin64
                                }
                                else
                                #>

                                if($enable32BitAppOnWin64 -ne $null) {
                                    LogVerbose "Setting app pool $name enable32BitAppOnWin64 to $enable32BitAppOnWin64"
                                    Set-ItemProperty -Path "IIS:\AppPools\$name" -Name enable32BitAppOnWin64 -Value $enable32BitAppOnWin64
                                }

                                if ($start) {
                                    LogVerbose "Starting app pool $name"
                                    Start-WebAppPool -Name $name
                                }

                                Log "SUCCESS: Created/updated application pool $name"
                            }
                            Catch {
                                LogError ("Unable to create application pool $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.DeleteApplicationPool" {
                        ValidateParamNames $action @("Name")
                        $names = GetActionParams $action "Name" $True
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Remove-WebAppPool")) {
                            LogError "Unable to attempt action; Remove-WebAppPool cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                foreach($name in $names) {
                                    if(Test-Path "IIS:\AppPools\$name") {
                                        LogVerbose "Stopping application pool $name"
                                        Stop-WebAppPool "$name"
                                        LogVerbose "Removing application pool $name"
                                        Remove-WebAppPool "$name"
                                        Log "SUCCESS: Removed application pool $name"
                                    }
                                    else {
                                        # this is not an "error" - the intended outcome is the app pool doesn't exist
                                        LogVerbose "Application pool $name already does not exist"
                                    }
                                }
                            }
                            Catch {
                                LogError ("Failed to remove application pool $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.StartApplicationPool" {
                        ValidateParamNames $action @("Name")
                        $names = GetActionParams $action "Name" $True
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Start-WebAppPool")) {
                            LogError "Unable to attempt action; Start-WebAppPool cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($name in $names) {
                                Try {
                                    if(Test-Path "IIS:\AppPools\$name") {
                                        Start-WebAppPool "$name"
                                        Log "SUCCESS: Started application pool $name"
                                    }
                                }
                                Catch {
                                    LogError ("Failed to start application pool $name")
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "IIS.StopApplicationPool" {
                        ValidateParamNames $action @("Name")
                        $names = GetActionParams $action "Name" $True
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Stop-WebAppPool")) {
                            LogError "Unable to attempt action; Stop-WebAppPool cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($name in $names) {
                                Try {
                                    if(Test-Path "IIS:\AppPools\$name") {
                                        Stop-WebAppPool "$name"
                                        Log "SUCCESS: Stopped application pool $name"
                                    }
                                }
                                Catch {
                                    LogError ("Failed to stop application pool $name")
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "IIS.CreateSite" {
                        ValidateParamNames $action @("Name","Folder","ApplicationPool","Binding","DefaultPort80Binding", "ExactBindings", "AnonymousAuth","AnonymousAuthUserName","WindowsAuth","FormsAuth","LoggingFolder", "BasicAuth")
                        $name = GetActionParam $action "Name" $True
                        $folder = GetActionParam $action "Folder" $True
                        $applicationPool = GetActionParam $action "ApplicationPool" $False
                        $bindings = GetActionParams $action "Binding" $False
                        $defaultPort80Binding = GetActionParam $action "DefaultPort80Binding" $False $True @("[BOOL]")
                        $defaultPort80Binding = (($defaultPort80Binding -ieq "true") -or ($defaultPort80Binding -eq $True))
                        $exactBindings = GetActionParam $action "ExactBindings" $False $True @("[BOOL]")
                        $exactBindings = (($exactBindings -ieq "true") -or ($exactBindings -eq $True))
                        $anonymousAuth = GetActionParam $action "AnonymousAuth" $False $null @("[ENUM]","","false","true")
                        $anonymousAuthUserName = GetActionParam $action "AnonymousAuthUserName" $False $null
                        $windowsAuth = GetActionParam $action "WindowsAuth" $False $null @("[ENUM]","","false","true")
                        $formsAuth = GetActionParam $action "FormsAuth" $False $null @("[ENUM]","","false","true")
                        $loggingFolder = GetActionParam $action "LoggingFolder" $False
                        $basicAuth = GetActionParam $action "BasicAuth" $False $null @("[ENUM]","","false","true")
                        Log "  Name=$name"
                        Log "  Folder=$folder"
                        Log "  ApplicationPool=$applicationPool"
                        foreach($binding in $bindings) { Log "  Binding=$binding" }
                        Log "  DefaultPort80Binding=$defaultPort80Binding"
                        Log "  AnonymousAuth=$anonymousAuth"
                        Log "  AnonymousAuthUserName=$anonymousAuthUserName"
                        Log "  WindowsAuth=$windowsAuth"
                        Log "  FormsAuth=$formsAuth"
                        Log "  LoggingFolder=$loggingFolder"
                        Log "  BasicAuth=$basicAuth"

                        if(-not (PSCmdletAvailable "New-WebSite")) {
                            LogError "Unable to attempt action; New-WebSite cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # make sure folder exists
                                if (-not (Test-Path $folder -PathType Container)) {
                                    LogVerbose "Creating $folder"
                                    New-Item -Path $folder -ItemType Directory | Out-Null
                                }
                                if(Test-Path "IIS:\Sites\$name") {
                                    # force site properties for application pool and folder
                                    LogVerbose "Site $name already exists, forcing app pool to $applicationPool and physical path to $folder"
                                    Set-ItemProperty "IIS:\Sites\$name" -Name ApplicationPool $applicationPool
                                    Set-ItemProperty "IIS:\Sites\$name" -Name physicalPath -Value $folder
                                }
                                else {
                                    LogVerbose "Creating new site $name with app pool $applicationPool and physical path $folder"
                                    
                                    #Workaround for a bug that exists with New-Website when no site exists in IIS. 
                                    $siteID = (Get-ChildItem 'IIS:\Sites' | ForEach {$_.id} | sort -Descending | Select -First 1) + 1

                                    New-Website -Name $name -PhysicalPath $folder -ApplicationPool $applicationPool -Id $siteID | Out-Null
                                }
                                # add in all new bindings that are not already there
                                $bindingList = @()
                                $bindings | % {
                                    # e.g. Protocol=http;HostHeader=intr-p-mysite;Port=80;IPAddress=*
                                    LogVerbose("Parsing $_  into Protocol, HostHeader, Port, IPAddress")
                                    $bindingKeyValues = KeyValuePairs "$_" ";" "=" "Protocol,HostHeader,Port,IPAddress"
                                    $protocol = GetKeyValue $bindingKeyValues "Protocol" "http"
                                    $hostHeader = GetKeyValue $bindingKeyValues "HostHeader" ""
                                    $port = GetKeyValue $bindingKeyValues "Port" "80"
                                    $IPAddress = GetKeyValue $bindingKeyValues "IPAddress" "*"
                                    # append to a list of all we binding the XML specified - see $exactBindings test below
                                    $bindingList += [array]"$protocol;$($IPAddress):$($port):$($hostHeader)"

                                    if((Get-WebBinding -Name $name -Protocol $protocol -HostHeader $hostHeader -Port $port -IPAddress $IPAddress) -eq $null) {
                                        LogVerbose "Adding new binding to site $($name): protocol=$protocol, hostheader=$hostHeader, port=$port, IPAddress=$IPAddress"
                                        New-WebBinding -Name $name -Protocol $protocol -HostHeader $hostHeader -Port $port -IPAddress $IPAddress
                                    }
                                }
                                # are we keeping ONLY the specified bindings?
                                if($exactBindings) {
                                    (Get-WebBinding -Name "$name") | % {
                                        if(-not ($bindingList -icontains [string]::concat($_.protocol, ';', $_.bindingInformation))) {
                                            LogVerbose "Removing additional binding $([string]::concat($_.protocol, ';', $_.bindingInformation)))"
                                            $_ | Remove-WebBinding
                                        }
                                    }
                                }
                                # remove the default port if requested
                                if($defaultPort80Binding -eq $false) {
                                    $port80Bindings = (Get-WebBinding -Name "$name" -Protocol "http" -Port 80 -IPAddress "*" -HostHeader "")
                                    if($port80Bindings -ne $null) {
                                        $port80Bindings | % {
                                            if(($_.BindingInformation -ieq '*:80:') -and ($_.Protocol -ieq 'http')) {
                                                LogVerbose "Removing default port 80 binding"
                                                $_ | Remove-WebBinding
                                            }
                                        }
                                    }
                                }
                                if($anonymousAuth -eq "") {
                                    LogVerbose "Removing site $name AnonymousAuth property"
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled
                                }
                                elseif($anonymousAuth -ne $null) {
                                    LogVerbose "Setting site $name AnonymousAuth property to $anonymousAuth"
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value $anonymousAuth
                                }
                                if($anonymousAuthUserName -ne $null) {
                                    LogVerbose "Setting site $name AnonymousAuth user name property to $anonymousAuthUserName"
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$site" -Filter system.webServer/security/authentication/anonymousauthentication -Name userName -Value $anonymousAuthUserName
                                }
                                if($windowsAuth -eq "") {
                                    LogVerbose "Removing site $name WindowsAuth property"
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                }
                                elseif($windowsAuth -ne $null) {
                                    LogVerbose "Setting site $name WindowsAuth property to $windowsAuth"
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value $windowsAuth
                                }
                                if([string]::IsNullOrEmpty($basicAuth)) {
                                    Try {
                                    LogVerbose "Removing site $name BasicAuth property"
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/basicAuthentication -Name Enabled
                                    }
                                    #This catch is a work around for blank BasicAuth value in the XML.  
                                    Catch {}
                                }
                                elseif($basicAuth -ne $null) {
                                    LogVerbose "Setting site $name BasicAuth property to $windowsAuth"
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites" -Location "$name" -Filter /system.webServer/security/authentication/basicAuthentication -Name Enabled -Value $basicAuth
                                }
                                if($loggingFolder -eq "") {
                                    LogVerbose "Removing site $name logging folder override"
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$name" -Name logfile.directory
                                }
                                elseif($loggingFolder -ne $null) {
                                    if (-not (Test-Path $loggingFolder -PathType Container)) {
                                        LogVerbose "Creating $loggingFolder"
                                        New-Item -Path $loggingFolder -ItemType Directory | Out-Null
                                    }
                                    LogVerbose "Setting site $name logging folder override to $loggingFolder"
                                    Set-ItemProperty "IIS:\Sites\$name" -name logFile -value @{directory="$loggingFolder"}
                                }
                                Log "SUCCESS: Created/updated site $name"
                            }
                            Catch {
                                LogError ("Unable to create/update site $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }


                    "IIS.DeleteSite" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Remove-Website")) {
                            LogError "Unable to attempt action; Remove-Website cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # wipe out all applications under site
                                if(Test-Path "IIS:\Sites\$name") {
                                    foreach ($app in (get-item "IIS:\Sites\$name\*").Name) {
                                        LogVerbose "Deleting site $name application $app"
                                        Remove-WebApplication -Name "$app" -Site "$name"
                                    }
                                    LogVerbose "Deleting site $name"
                                    Remove-WebSite -Name "$name"
                                    Log "SUCCESS: Deleted site $name"
                                }
                                else {
                                    LogVerbose "Site $name already does not exist"
                                }
                            }
                            Catch {
                                LogError ("Unable to delete site $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.StartSite" {
                        ValidateParamNames $action @("Name")
                        $names = GetActionParams $action "Name" $True
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Start-WebSite")) {
                            LogError "Unable to attempt action; Start-WebSite cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($name in $names) {
                                Try {
                                    if(Test-Path "IIS:\Sites\$name") {
                                        Start-WebSite "$name"
                                        Log "SUCCESS: Started website $name"
                                    }
                                }
                                Catch {
                                    LogError ("Failed to start website $name")
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "IIS.StopSite" {
                        ValidateParamNames $action @("Name")
                        $names = GetActionParams $action "Name" $True
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Stop-WebSite")) {
                            LogError "Unable to attempt action; Stop-WebSite cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($name in $names) {
                                Try {
                                    if(Test-Path "IIS:\Sites\$name") {
                                        Stop-WebSite "$name"
                                        Log "SUCCESS: Stopped website $name"
                                    }
                                }
                                Catch {
                                    LogError ("Failed to stop website $name")
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "IIS.CreateApplication" {
                        ValidateParamNames $action @("Site","Name","Folder","ApplicationPool","AnonymousAuth","AnonymousAuthUserName","WindowsAuth","FormsAuth")
                        $site = GetActionParam $action "Site" $True
                        $name = GetActionParam $action "Name" $True
                        $folder = GetActionParam $action "Folder" $True
                        $applicationPool = GetActionParam $action "ApplicationPool" $False
                        $anonymousAuth = GetActionParam $action "AnonymousAuth" $False $null @("[BOOLB]")
                        $anonymousAuthUserName = GetActionParam $action "AnonymousAuthUserName" $False $null
                        $windowsAuth = GetActionParam $action "WindowsAuth" $False $null @("[BOOLB]")
                        $formsAuth = GetActionParam $action "FormsAuth" $False $null @("[BOOLB]")
                        Log "  Site=$site"
                        Log "  Name=$name"
                        Log "  Folder=$folder"
                        Log "  ApplicationPool=$applicationPool"
                        Log "  AnonymousAuth=$anonymousAuth"
                        Log "  AnonymousAuthUserName=$anonymousAuthUserName"
                        Log "  WindowsAuth=$windowsAuth"
                        Log "  FormsAuth=$formsAuth"

                        if(-not (PSCmdletAvailable "New-WebApplication")) {
                            LogError "Unable to attempt action; New-WebApplication cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # make sure folder exists
                                if (-not (Test-Path $folder -PathType Container)) {
                                    LogVerbose "Creating $folder"
                                    New-Item -Path $folder -ItemType Directory | Out-Null
                                }

                                # create the app unless it already exists
                                if((Get-WebApplication -Site "$site" -Name "$name") -eq $null) {
                                    New-WebApplication -Site "$site" -Name "$name" -PhysicalPath "$folder" -ApplicationPool "$applicationPool" | Out-Null
                                }
                                else {
                                    LogVerbose ("Site $site application $name already exists")

                                    # force the application pool & physical folder
                                    Set-ItemProperty "IIS:\Sites\$site\$name" -Name ApplicationPool "$applicationPool"
                                    Set-ItemProperty "IIS:\Sites\$site\$name" -Name physicalPath -Value "$folder"
                                }

                                # set $anonymousAuth, $windowsAuth, $formsAuth
                                if($anonymousAuth -eq "") {
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled
                                }
                                elseif($anonymousAuth -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value $anonymousAuth
                                }
                                if($anonymousAuthUserName -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter system.webServer/security/authentication/anonymousauthentication -Name userName -Value $anonymousAuthUserName
                                }
                                if($windowsAuth -eq "") {
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                }
                                elseif($windowsAuth -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value $windowsAuth
                                }
                                if($formsAuth -eq "") {
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                }
                                elseif($formsAuth -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$name" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value $formsAuth
                                }

                                Log "SUCCESS: Created/updated site $site application $name"
                            }
                            Catch {
                                LogError ("Unable to create/update site $site application $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.DeleteApplication" {
                        ValidateParamNames $action @("Site","Name")
                        $site = GetActionParam $action "Site" $True
                        $names = GetActionParams $action "Name" $True
                        Log "  Site=$site"
                        foreach($name in $names) { Log "  Name=$name" }

                        if(-not (PSCmdletAvailable "Remove-WebApplication")) {
                            LogError "Unable to attempt action; Remove-WebApplication cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($name in $names) {
                                Try {
                                    if((Get-WebApplication -Site "$site" -Name "$name") -ne $null) {
                                        Remove-WebApplication -Name "$name" -Site "$site"
                                        Log "SUCCESS: Removed app $name under site $site"
                                    }
                                }
                                Catch {
                                    LogError ("Unable to delete app $name under site $site")
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "IIS.SectionAllowOverride" {
                        # typically system.webServer/security/authentication/anonymousAuthentication
                        #        or system.webServer/security/authentication/windowsAuthentication
                        ValidateParamNames $action @("Section","OverrideMode")
                        $sections = GetActionParams $action "Section" $True
                        $overrideMode = GetActionParam $action "Allow" $False "allow" @("[ENUM]", "allow", "deny")
                        foreach($section in $sections) { Log "  Section=$section" }
                        Log "  OverrideMode=$overrideMode"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
                                foreach($section in $sections) {
                                    $IISServerManager = new-object Microsoft.Web.Administration.ServerManager
                                    $IISGlobalConfig = $IISServerManager.GetApplicationHostConfiguration()
                                    $IISSectionConfig = $IISGlobalConfig.GetSection($section)
                                    $IISSectionConfig.OverrideMode = $overrideMode
                                    $IISServerManager.CommitChanges()
                                    Log ("SUCCESS: Set section $section override mode to $overrideMode")
                                }
                            }
                            Catch {
                                LogError ("Unable to set one or more section(s) override mode to $overrideMode")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.Browse" {
                        ValidateParamNames $action @("URL","Visible")
                        $url = GetActionParam $action "URL" $True
                        $visible = GetActionParam $action "Visible" $False $True @("[BOOL]")
                        $visible = (($visible -ieq "true") -or ($visible -eq $True))
                        Log "  URL=$url"
                        Log "  Visible=$visible"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                $IE=new-object -com internetexplorer.application
                                $IE.navigate2("$url")
                                $IE.visible=$visible
                                Start-Sleep 3
                                $IE.Quit()
                                Log ("SUCCESS: Browsed to $url")
                            }
                            Catch {
                                LogError ("Unable to browse to $url")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.CreateVirtualDirectory" {
                        ValidateParamNames $action @("Site", "Name", "Application", "PhysicalPath")
                        $site = GetActionParam $action "Site" $True
                        $name = GetActionParam $action "Name" $True
                        $application = GetActionParam $action "Application" $False "/"
                        $physicalPath = GetActionParam $action "PhysicalPath" $True
                        Log "  Site=$site"
                        Log "  Name=$name"
                        Log "  Application=$application"
                        Log "  PhysicalPath=$physicalPath"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if (Test-Path "IIS:\Sites\$site") {
                                    LogVerbose ("Site exists checking if application exists")

                                    #Make virtual directory at the site root
                                    if ($application -eq "/") {
                                        LogVerbose ("Make virtual directory at the site root")
                                        if([bool]$(Get-WebVirtualDirectory -Site $site -Name $name)) {
                                            if ($(Get-WebVirtualDirectory -Site $site -Name $name).PhysicalPath -eq $physicalPath) {
                                                LogVerbose ("Virtual directory already exists")
                                            }
                                            else {
                                                LogVerbose ("Virtual directory has wrong physical path so recreate it")

                                                Remove-WebVirtualDirectory -Site $site -Name $name | Out-Null

                                                if(-not $(Test-Path "$physicalPath")) { 
                                                    New-Item -Type Directory -Path "$physicalPath"
                                                }

                                                New-WebVirtualDirectory -Site $site -PhysicalPath $physicalPath -Name $name | Out-Null
                                                Log ("SUCCESS: Created virtual directory")
                                            }
                                        }
                                        else {
                                            if(-not $(Test-Path "$physicalPath")) { 
                                                New-Item -Type Directory -Path "$physicalPath"
                                            }

                                            New-WebVirtualDirectory -Site $site -PhysicalPath $physicalPath -Name $name | Out-Null
                                            Log ("SUCCESS: Created virtual directory")
                                        }
                                    }
                                    #Actual application has been specified
                                    else {
                                        LogVerbose ("Make virtual directory at the application $application")
                                        if([bool]$(Get-WebApplication -Site $site -Application $application)) {
                                            if([bool]$(Get-WebVirtualDirectory -Site $site -Application $application -Name $name)) {
                                                if ($(Get-WebVirtualDirectory -Site $site -Application $application -Name $name).PhysicalPath -eq $physicalPath) {
                                                    LogVerbose ("Virtual directory already exists")
                                                }
                                                else {
                                                    LogVerbose ("Virtual directory has wrong physical path so recreate it")

                                                    Remove-WebVirtualDirectory -Site $site -Name $name | Out-Null

                                                    if(-not $(Test-Path "$physicalPath")) { 
                                                        New-Item -Type Directory -Path "$physicalPath"
                                                    }

                                                    New-WebVirtualDirectory -Site $site -Application $application -PhysicalPath $physicalPath -Name $name | Out-Null
                                                    Log ("SUCCESS: Created virtual directory")
                                                }
                                            }
                                            else {
                                                if(-not $(Test-Path "$physicalPath")) { 
                                                    New-Item -Type Directory -Path "$physicalPath"
                                                }

                                                New-WebVirtualDirectory -Site $site -Application $application -PhysicalPath $physicalPath -Name $name | Out-Null
                                                Log ("SUCCESS: Created virtual directory")
                                            }
                                        }
                                        else {
                                            LogError ("Failed to create virtual directory. Cannot create a virtual directory for a site that does not exist")
                                            $actionSuccess = $False
                                        }
                                    }
                                }
                                else {
                                    LogError ("Failed to create virtual directory. Cannot create a virtual directory for a site that does not exist")
                                    $actionSuccess = $False
                                }
                            }
                            Catch {
                                LogError ("Failed to create virtual directory $name with path $physicalPath")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.DeleteVirtualDirectory" {
                        ValidateParamNames $action @("Site", "Name", "Application")
                        $site = GetActionParam $action "Site" $True
                        $name = GetActionParam $action "Name" $True
                        $application = GetActionParam $action "Application" $False "/"
                        Log "  Site=$site"
                        Log "  Name=$name"
                        Log "  Application=$application"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if([bool]$(Get-WebVirtualDirectory -Site $site -Name $name -Application $application)) {
                                    Remove-WebVirtualDirectory -Site $site -Name $name -Application $application | Out-Null
                                }
                            }
                            Catch {
                                LogError ("Failed to remove virtual directory $name")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.HandlerUnlock" {
                        ValidateParamNames $action @()

                        if(-not $whatIf.IsPresent) {
                            Try {
                                $assembly = [System.Reflection.Assembly]::LoadFrom("$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll")
                                $manager = new-object Microsoft.Web.Administration.ServerManager
                                $config = $manager.GetApplicationHostConfiguration()
                                $section = $config.GetSection('system.webServer/handlers')
                                $section.OverrideMode = 'Allow'
                                $manager.CommitChanges()
                                Log "SUCCESS: IIS Handlers have been unlocked"
                            }
                            Catch {
                                LogError "Unable to unlock IIS Handlers"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.AddISAPIFilter" {
                        ValidateParamNames $action @("Name","Path","PreCondition")
                        $isapiName = GetActionParams $action "Name" $True
                        $isapiPath = GetActionParams $action "Path" $True
                        $preCondition = GetActionParams $action "PreCondition" $False
                        Log "  Name=$isapiName"
                        Log "  Path=$isapiPath"
                        Log "  PreCondition=$preCondition"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if(Test-Path "$isapiPath" -PathType Leaf) {
                                    if((Get-WebConfiguration -PSPath 'IIS:\' -Filter "/system.webServer/isapiFilters/filter" | Where-Object -Property "name" -EQ "$isapiName") -eq $null)
                                    {
                                        Add-WebConfiguration -PSPath 'IIS:\Sites' -Filter "/system.webServer/isapiFilters" -Value @{
                                            name = "$isapiName";
		                                    path = "$isapiPath";
		                                    preCondition = "$preConditionIfAny"
                                        }
                                    } else {
                                        Log "  ISAPI Filter $isapiName is already installed"
                                    }
                                } else {
                                    LogError "  $isapiName was not located at $isapiPath"
                                    $actionSuccess = $False
                                }
                            }
                            Catch {
                                LogError "Unable to add $isapiName to AppHost.config"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "IIS.RemoveISAPIFilter" {
                        ValidateParamNames $action @("Name")
                        $isapiName = GetActionParams $action "Name" $True
                        Log "  Name=$isapiName"

                        if(-not $whatIf.IsPresent) {
                          Try {
                              if((Get-WebConfiguration -PSPath 'IIS:\' -Filter "/system.webServer/isapiFilters/filter" | Where-Object -Property name -EQ $isapiName) -ne $null)  {
                                  Clear-WebConfiguration -PSPath 'IIS:\' -Filter "/system.webServer/isapiFilters/filter[@name='$isapiName']" | Out-Null
                              }
                          }
                          Catch {
                              LogError "Unable to remove $isapiName from AppHost.config"
                              Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                              Log ("  Exception Message: $($_.Exception.Message)")
                              $actionSuccess = $False
                          }
                        }
                    }
                    
                    "Hosts.Add" {
                        ValidateParamNames $action @("LocalAlias")
                        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
                        $localIP = "127.0.0.1"
                        $localAliases = GetActionParams $action "LocalAlias" $False
                        foreach($localAlias in $localAliases) {Log "    LocalAlias=$localAlias" }
                        Log "  HostsFile=$hostsFile"
                        Log "  LocalIPAddress=$localIP"                       

                        if(-not $whatIf.IsPresent) {
                            if(Test-Path "$hostsFile" -PathType Leaf) {
                                foreach ($localAlias in $localAliases) {
                                    Try {
                                            #add the new alias if not already present
                                            if (!(Get-Content "$hostsFile" | Select-String "$localAlias")) {
                                                Add-Content "$hostsFile" "`n`t$localIP       $localAlias" | Out-Null
                                            }
                                            if (!(Get-Content "$hostsFile" | Select-String "$localAlias")) {
                                                LogError "$localAlias was not found in $hostsFile"
                                                $actionSuccess = $False
                                            }
                                    }
                                    Catch {
                                        LogError "Unable to add $localAlias to $hostsFile"
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }
                            } else {
                                LogError "Unable to locate $hostsFile"
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.Copy" {
                        ValidateParamNames $action @("Source","Destination","Recurse","Overwrite")
                        $source = GetActionParam $action "Source" $True
                        $destination = GetActionParam $action "Destination" $True
                        $recurse = GetActionParam $action "Recurse" $False "True" @("[BOOL]")
                        $recurse = (($recurse -ieq "true") -or ($recurse -eq $True))
                        $overwrite = GetActionParam $action "Overwrite" $False "always" @("[ENUM]", "always", "never", "ifnewer")
                        Log "  Source=$source"
                        Log "  Destination=$destination"
                        Log "  Recurse=$recurse"
                        Log "  Overwrite=$overwrite"

                        if(-not $whatIf.IsPresent) {
                            # is it a folder copy?
                            if($source.Contains("*") -or $source.Contains("?") -or ($fileTest = (Test-Path $source -PathType Container))) {
                                LogVerbose("$source appears to refer to a folder")
                                # if the destination is already a file, fail
                                if($fileTest = (Test-Path $destination -PathType Leaf)) {
                                    LogError "Unable to copy $source to $destination; Destination is an existing file"
                                    $actionSuccess = $False
                                }
                                else {
                                    # build the full source path - start with did we already use wildcards?
                                    if((-not $source.Contains("*")) -and (-not $source.Contains("?"))) {
                                        if(-not $source.EndsWith('\')) { $source += "\" }
                                        $source += "*.*"
                                    }
                                    $sourceDirLength = $source.LastIndexOf('\')

                                    if($recurse) {
                                        $sourceFiles = Get-ChildItem $source -Recurse
                                    }
                                    else {
                                        $sourceFiles = Get-ChildItem $source
                                    }
                                    $destination = $destination.TrimEnd("\")
                                    LogVerbose "Found $($sourceFiles.Length) file(s) to copy in $sourceFiles"

                                    foreach($sourceFile in $sourceFiles) {
                                        Try {
                                            # calculate the dest file name and create dest folder if needed
                                            $destinationFileName = [string]::Concat($destination.TrimEnd("\"), $sourceFile.FullName.Substring($sourceDirLength))
                                            $destinationFolder = $destinationFileName.SubString(0, $destinationFileName.LastIndexOf('\'))
                                            if (-not (Test-Path $destinationFolder -PathType Container)) {
                                                LogVerbose "Creating folder $destinationFolder"
                                                New-Item -Path $destinationFolder -ItemType Directory | Out-Null
                                            }

                                            $destinationFileExists = (Test-Path $destinationFileName -PathType Leaf)
                                            # if it's always, never but doesn't exist, ifnewer but doesn't exist, just copy it
                                            if(($overwrite -ieq "always") -or (($overwrite -ieq "never") -and (-not ($destinationFileExists))) -or (($overwrite -ieq "ifnewer") -and (-not ($destinationFileExists)))) {
                                                LogVerbose("Copying file $($sourceFile.FullName) to $destinationFileName")
                                                Copy-Item -Path $sourceFile.FullName -Destination $destinationFileName -Force
                                                Log ("SUCCESS: Copied $($sourceFile.FullName) to $destinationFileName")
                                            }
                                            elseif (($overwrite -ieq "ifnewer") -and $destinationFileExists) {
                                                if($sourceFile.LastWriteTime -gt (Get-Item $destinationFileName).LastWriteTime) {
                                                    LogVerbose("Copying file $($sourceFile.FullName) to $destinationFileName")
                                                    Copy-Item -Path $sourceFile.FullName -Destination $destinationFileName -Force
                                                    Log ("SUCCESS: Copied $($sourceFile.FullName) to $destinationFileName")
                                                }
                                                else {
                                                    LogVerbose("Not copying file $($sourceFile.FullName) to $destinationFileName because the source file isn't newer than the destination")
                                                }
                                            }
                                        }
                                        Catch {
                                            LogError "Failed to copy $source to $destination"
                                            Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                            Log ("  Exception Message: $($_.Exception.Message)")
                                            $actionSuccess = $False
                                        }
                                    }
                                }
                            }
                            # it had better be a file that exists...
                            elseif ($fileTest = (Test-Path $source -PathType Leaf)) {
                                LogVerbose("$source appears to refer to a file")
                                # calculate the destination file name
                                $destinationFileName = $destination
                                if($destinationIsFolder = (Test-Path $destination -PathType Container)) {
                                    if(-not $destinationFileName.EndsWith('\')) { $destinationFileName += "\" }
                                    $destinationFileName += $source.SubString($source.LastIndexOf('\') + 1)
                                }
                                LogVerbose("Destination file = $destinationFileName")

                                Try {
                                    $destinationFileExists = (Test-Path $destinationFileName -PathType Leaf)
                                    # if it's always, never but doesn't exist, ifnewer but doesn't exist, just copy it
                                    if(($overwrite -ieq "always") -or (($overwrite -ieq "never") -and (-not ($destinationFileExists))) -or (($overwrite -ieq "ifnewer") -and (-not ($destinationFileExists)))) {
                                        LogVerbose "Copying $source to $destinationFileName"
                                        Copy-Item -Path $source -Destination $destinationFileName -Force
                                        Log "SUCCESS: Copied $source to $destinationFileName"
                                    }
                                    elseif (($overwrite -ieq "ifnewer") -and $destinationFileExists) {
                                        if((Get-Item $source).LastWriteTime -gt (Get-Item $destinationFileName).LastWriteTime) {
                                            LogVerbose "Copying $source to $destinationFileName"
                                            Copy-Item -Path $source -Destination $destinationFileName -Force
                                            Log "SUCCESS: Copied $source to $destinationFileName"
                                        }
                                        else {
                                            LogVerbose("Not copying file $source to $destinationFileName because the source file isn't newer than the destination")
                                        }
                                    }
                                }
                                Catch {
                                    LogError "Failed to copy $source to $destinationFileName"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                            else {
                                LogError "Unable to copy $source to $destination; Source does not exist"
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.CreateFolder" {
                        ValidateParamNames $action @("Folder")
                        $folders = GetActionParams $action "Folder" $False
                        foreach($folder in $folders) { Log "  Folder=$folder" }

                        if(-not $whatIf.IsPresent) {
                            foreach($folder in $folders) {
                                if (-not (Test-Path $folder -PathType Container)) {
                                    Try {
                                        LogVerbose "Creating $folder"
                                        New-Item -Path $folder -ItemType Directory | Out-Null
                                        Log "SUCCESS: Created folder $folder"
                                    }
                                    Catch {
                                        LogError "Unable to create directory $folder"
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }
                                else {
                                    LogVerbose "$folder already exists"
                                }
                            }
                        }
                    }

                    "FileIO.DeleteFolder" {
                        ValidateParamNames $action @("Folder","DeleteContents")
                        $folder = GetActionParam $action "Folder" $False
                        $deleteContents = GetActionParam $action "DeleteContents" "NoContents" @("[ENUM]", "NoContents", "FolderAndContents", "OnlyContents")
                        $allowRoot = GetActionParam $action "AllowRoot" $False $False @("[BOOL]")
                        $allowRoot = ($allowRoot -ieq $true) -or ($allowRoot -ieq "true")
                        Log "  Folder=$folder"
                        Log "  DeleteContents=$deleteContents"
                        Log "  AllowRoot=$allowRoot"

                        if(-not $whatIf.IsPresent) {
                            # normalize folder to not end with '\'
                            if ($folder.EndsWith("\")) { $folder.TrimEnd('\') }
                            # a "root" has a colon and no additional backslashes
                            $isRoot = ($folder.Contains(":")) -and (-not $folder.Contains('\'))

                            # if the folder doesn't exist, we're done!
                            if ($isRoot -or (Test-Path "$folder" -PathType Container)) {
                                # if the user is not allowing this to be called on a root, error
                                if(-not $allowRoot -and $isRoot) {
                                    LogError ("Script does not give permission to call this action on a root $folder")
                                    $actionSuccess = $False
                                }
                                # you can't delete a root
                                elseif(($deleteContents -ine "OnlyContents") -and $isRoot) {
                                    LogError ("You can only use OnlyContents on root folder $folder")
                                    $actionSuccess = $False
                                }
                                # are we deleting only the folder itself?
                                elseif($deleteContents -ieq "NoContents") {
                                    LogVerbose "Only attempting to delete the root folder but no contents in it"
                                    $folderContents = Get-ChildItem "$folder" -Recurse
                                    if($folderContents.Length -eq 0) {
                                        Remove-Item "$folder"
                                        Log ("SUCCESS: Deleted empty folder $folder")
                                    }
                                    else {
                                        LogError ("Folder $folder is not empty and action does not give permission to delete contents")
                                        $actionSuccess = $False
                                    }
                                }
                                else {
                                    LogVerbose "Attempt to delete all contents (files and folders) of the folder"
                                    Remove-Item "$folder\*" -Recurse

                                    if($deleteContents -ieq "FolderAndContents") {
                                        LogVerbose "Attempt to delete the root folder"
                                        $folderContents = Get-ChildItem "$folder" -Recurse
                                        if($folderContents.Length -eq 0) {
                                            Remove-Item "$folder"
                                            Log ("SUCCESS: Deleted all contents of $folder and the folder itself")
                                        }
                                        else {
                                            LogError ("Unable to delete entire contents of $folder before attempting to delete the folder itself")
                                            $actionSuccess = $False
                                        }
                                    }
                                    else {
                                        Log ("SUCCESS: Deleted all contents of $folder")
                                    }
                                }
                            }
                            else {
                                LogVerbose "Folder already does not exist"
                            }
                        }
                    }

                    "FileIO.ShareFolder" {
                        ValidateParamNames $action @("Name","Folder","Remark","GrantRead","GrantFull","GrantChange","Deny")
                        $name = GetActionParam $action "Name" $True
                        $folder = GetActionParam $action "Folder" $True
                        $remark = GetActionParam $action "Remark" $False $null
                        $grantReads = GetActionParams $action "GrantRead" $False
                        $grantFulls = GetActionParams $action "GrantFull" $False
                        $grantChanges = GetActionParams $action "GrantChange" $False
                        $denys = GetActionParams $action "Deny" $False
                        Log "  Name=$name"
                        Log "  Folder=$folder"
                        Log "  Remark=$remark"
                        foreach($grant in $grantFulls) { Log "  GrantFull=$grant" }
                        foreach($grant in $grantChanges) { Log "  GrantChange=$grant" }
                        foreach($grant in $grantReads) { Log "  GrantRead=$grant" }
                        foreach($deny in $denys) { Log "  Deny=$deny" }

                        if(-not $WhatIf.IsPresent) {
                            # attempt to wipe out existing share (to recreate it)
                            Try { cmd /c "net share ""$name"" /DELETE" | Out-Null } Catch { }

                            Try {
                                # build command line to execute
                                $strCommand = "net share ""$name""=""$folder"""
                                # append the grants
                                foreach($grant in $grantFulls) {
                                    $strCommand = [string]::Concat($strCommand, " ""/GRANT:$grant,FULL""")
                                }
                                foreach($grant in $grantChanges) {
                                    $strCommand = [string]::Concat($strCommand, " ""/GRANT:$grant,CHANGE""")
                                }
                                foreach($grant in $grantReads) {
                                    $strCommand = [string]::Concat($strCommand, " ""/GRANT:$grant,READ""")
                                }
                                foreach($grant in $grantDeny) {
                                    $strCommand = [string]::Concat($strCommand, " ""/GRANT:$grant,DENY""")
                                }
                                if($remark -ne $null) {
                                    $strCommand = [string]::Concat($strCommand, " ""/REMARK:$remark""")
                                }

                                # create new share
                                LogVerbose "Executing cmd.exe $strCommand"
                                cmd /c "$strCommand" | Out-Null
                                $returnCode = $LASTEXITCODE
                                if($returnCode -ne "0") {
                                    LogError "Unable to create share $name using $strCommand"
                                    $actionSuccess = $False
                                }
                                else {
                                    Log("SUCCESS: Created share $name pointing to $folder")
                                }
                            }
                            Catch {
                                LogError ("Unable to create share $name pointing to $folder")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.FolderPermissions" {
                        ValidateParamNames $action @("Folder","Read","Write","Modify","FullControl","Execute","Revoke","ListedPermissionsOnly","Recurse","BreakInheritance")
                        $folder = GetActionParam $action "Folder" $True
                        $reads = GetActionParams $action "Read" $False
                        $writes = GetActionParams $action "Write" $False
                        $modifys = GetActionParams $action "Modify" $False
                        $fullControls = GetActionParams $action "FullControl" $False
                        $executes = GetActionParams $action "Execute" $False
                        $revokes = GetActionParams $action "Revoke" $False
                        $listedPermissionsOnly = GetActionParam $action "ListedPermissionsOnly" $False $False @("[BOOL]")
                        $listedPermissionsOnly = (($listedPermissionsOnly -ieq "true") -or ($listedPermissionsOnly -eq $True))
                        $recurse = GetActionParam $action "Recurse" $False $False @("[BOOL]")
                        $recurse = (($recurse -ieq "true") -or ($recurse -eq $True))
                        $breakInheritance = GetActionParam $action "BreakInheritance" $False $False @("[BOOL]")
                        $breakInheritance = (($breakInheritance -ieq "true") -or ($breakInheritance -eq $True))

                        Log "  Folder=$folder"
                        $reads | %{ Log "  Read=$_" }
                        $writes | %{ Log "  Write=$_" }
                        $modifys | %{ Log "  Modify=$_" }
                        $executes | %{ Log "  Execute=$_"}
                        $fullControls | %{ Log "  FullControl=$_" }
                        $revokes | %{ Log "  Revoke=$_" }
                        Log "  ListedPermissionsOnly=$listedPermissionsOnly"
                        Log "  Recurse=$recurse"

                        if(-not $whatIf.IsPresent) {
                            #Repair ACL if its fubar
                            Try {
                                $acl = Get-Acl $folder
                                Set-Acl -Path $folder -AclObject $acl
                            }
                            Catch {
                                Log ("  Folder ACL was corrupted but has been successfully repaired.")
                            }

                            #Now do actual work
                            Try {
                                $acl = Get-Acl $folder

                                if($breakInheritance) { 
                                    $acl.SetAccessRuleProtection($True, $True)
                                    Set-Acl -Path $folder -AclObject $acl
                                    $acl = Get-Acl $folder
                                }

                                if($recurse) { $inheritFlag = "ContainerInherit, ObjectInherit" } else { $inheritFlag = "None" }
                                $propFlag = "None"
                                $ruleType = "Allow"

                                if($listedPermissionsOnly) {
                                    $acl.Access | % {
                                        if ($_.IdentityReference -ne "NT AUTHORITY\SYSTEM") {
                                            $acl.RemoveAccessRule($_)
                                        }
                                    } | Out-Null
                                }

                                foreach ($read in $reads) {
                                    Try {
                                        $constructorParams = $read,"Read",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.AddAccessRule($accessRule)
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $read")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                foreach ($write in $writes) {
                                    Try {
                                        $constructorParams = $write,"Write",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.AddAccessRule($accessRule)
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $write")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                foreach ($modify in $modifys) {
                                    Try {
                                        $constructorParams = $modify,"Modify",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.AddAccessRule($accessRule)
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $modify")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                foreach ($fullControl in $fullControls) {
                                    Try {
                                        $constructorParams = $fullControl,"FullControl",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.AddAccessRule($accessRule)
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $fullControl")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                foreach ($execute in $executes) {
                                    Try {
                                        $constructorParams = $execute,"ReadAndExecute",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.AddAccessRule($accessRule)
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $execute")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                foreach ($revoke in $revokes) {
                                    Try {
                                        $constructorParams = $revoke,"FullControl",$inheritFlag,$propFlag,$ruleType
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $constructorParams
                                        $acl.RemoveAccessRule($accessRule) | Out-Null
                                    }
                                    Catch {
                                        LogError ("Unable to create access rule for $revoke")
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }

                                LogVerbose "Setting ACL to specified folder"
                                Set-Acl -Path $folder -AclObject $acl
							    Log("SUCCESS: Set ACL for $folder")
                            }
                            Catch {
                                LogError ("Unable to set ACL for $folder")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.Rename" {
                        ValidateParamNames $action @("Path","NewName")
                        $path = GetActionParam $action "Path" $True
                        $newName = GetActionParam $action "NewName" $True
                        Log "  Path=$path"
                        Log "  NewName=$newName"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if(-not (Test-Path "$path")) {
                                    LogError ("Unable to rename $path - does not exist")
                                    $actionSuccess = $False
                                }
                                else {
                                    Rename-Item -Path "$path" -NewName "$newName" -Force | Out-Null
                                    Log "SUCCESS: Renamed $path to $newName"
                                }
                            }
                            Catch {
                                LogError ("Unable to rename $path")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.Unzip" {
                        ValidateParamNames $action @("Path","Destination","ProgressDialog","YesToAll")
                        $path = GetActionParam $action "Path" $True
                        $destination = GetActionParam $action "Destination" $True
                        $progressDialog = GetActionParam $action "ProgressDialog" $False $False @("[BOOL]")
                        $progressDialog = (($progressDialog -ieq "true") -or ($progressDialog -eq $True))
                        $yesToAll = GetActionParam $action "YesToAll" $False $True @("[BOOL]")
                        $yesToAll = (($yesToAll -ieq "true") -or ($yesToAll -eq $True))
                        Log "  Path=$path"
                        Log "  Destination=$destination"
                        Log "  ProgressDialog=$progressDialog"
                        Log "  YesToAll=$yesToAll"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                $shell = New-Object -com shell.application
                                $zip = $shell.NameSpace($path)
                                # interesting bit flags (https://msdn.microsoft.com/en-us/library/windows/desktop/bb787866(v=vs.85).aspx)
                                # 4 = no progress dialog
                                # 16 = yes to all
                                # 512 = don't confirm new dir names
                                # 1024 = no UI for an error
                                $flags = (512 + 1024)
                                if($yesToAll) { $flags += 16 }
                                if(-not $progressDialog) { $flags += 4 }
                                foreach($item in $zip.items()) {
                                    $displayPath = $item.Path.Substring($path.Length)
                                    LogVerbose "Unzipping $displayPath to $destination"
                                    $shell.Namespace($destination).copyhere($item, $flags)
                                }
                                Log "SUCCESS: Unzipped $($zip.items().Count) items into $destination"
                            }
                            Catch {
                                LogError ("Unable to unzip file $path to $destination")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.UnblockFile" {
                        ValidateParamNames $action @("Path")
                        $paths = GetActionParams $action "Path" $False
                        foreach($path in $paths) { Log "  Path=$path" }

                        if(-not $whatIf.IsPresent) {
                            foreach($path in $paths) {
                                Try {
                                    Unblock-File "$path"
                                    Log "SUCCESS: Unblocked file $path"
                                }
                                Catch {
                                    LogError "Unable to unblock file $folder"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "FileIO.UnblockFolder" {
                        ValidateParamNames $action @("Folder")
                        $folders = GetActionParams $action "Folder" $False
                        foreach($folder in $folders) { Log "  Folder=$folder" }

                        if(-not $whatIf.IsPresent) {
                            # try each folder
                            foreach($folder in $folders) {
                                # get all files in folder and unblock each
                                $files = Get-ChildItem $folder -Recurse
                                LogVerbose "Unblocking $($files.Length) file(s) in $folder"
                                foreach($file in $files) {
                                    Try {
                                        Unblock-File $file.FullName
                                    }
                                    Catch {
                                        LogError "Unable to unblock $file"
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }
                                if($actionSuccess) {
                                    Log "SUCCESS: Unblocked $($files.Length) file(s) in $folder"
                                }
                            }
                        }
                    }

                    "FileIO.AppendToFile" {
                        ValidateParamNames $action @("Path","Text","Encoding","NewLineBefore")
                        $path = GetActionParam $action "Path" $True
                        $texts = GetActionParams $action "Text" $False
                        $encoding = GetActionParam $action "Encoding" $False "ASCII" @("[ENUM]", "Unknown", "String", "Unicode", "BigEndianUnicode", "UTF8", "UTF7", "UTF32", "ASCII", "Default", "OEM")
                        $newLineBefore = GetActionParam $action "NewLineBefore" $False $True @("[BOOL]")
                        $newLineBefore = (($NewLineBefore -ieq "true") -or ($NewLineBefore -eq $True))
                        Log "  Path=$path"
                        foreach($text in $texts) { Log "  Text=$text" }
                        Log "  Encoding=$encoding"
                        Log "  NewLineBefore=$newLineBefore"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                foreach($text in $texts) {
                                    # if path exists, append to it
                                    if(Test-Path "$path" -PathType Leaf) {
                                        LogVerbose "Appending text to $path"
                                        if($newLineBefore) {
                                            $text | Out-File -FilePath "$path" -Append -Force -Encoding $encoding
                                        }
                                        else {
                                            $text | Out-File -FilePath "$path" -Append -Force -Encoding $encoding -NoNewline
                                        }
                                    }
                                    # otherwise write a new file
                                    else {
                                        LogVerbose "Starting new file $path"
                                        if($newLineBefore) {
                                            $text | Out-File -FilePath "$path" -Encoding $encoding
                                        }
                                        else {
                                            $text | Out-File -FilePath "$path" -Encoding $encoding -NoNewline
                                        }
                                    }
                                }

                                Log "SUCCESS: Appended line(s) of text to $path"
                            }
                            Catch {
                                LogError "Unable to append line(s) of text to $path"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "FileIO.RegExReplace" {
                        ValidateParamNames $action @("Path","Find","Replace")
                        $paths = GetActionParams $action "Path" $True
                        $find = GetActionParam $action "Find" $True
                        $replace = GetActionParam $action "Replace" $True
                        foreach($path in $paths) { Log "  Path=$path" }
                        Log "  Find=$find"
                        Log "  Replace=$replace"

                        if(-not $whatIf.IsPresent) {
                            foreach($path in $paths) {
                                Try {
                                    if(Test-Path "$path" -PathType Leaf) {
                                        $fileContent = Get-Content "$path" | % { $_ -Replace "$find","$replace"}
                                        $fileContent | Set-Content "$path" -Force
                                    }
                                    else {
                                        LogVerbose "$path does not exist"
                                    }

                                    Log "SUCCESS: Replaced text in $path"
                                }
                                Catch {
                                    LogError "Unable to replace text in $path"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "Security.AddToLocalGroup" {
                        ValidateParamNames $action @("Group","Add")
                        $groups = GetActionParams $action "Group" $False
                        $adds = GetActionParams $action "Add" $False @("[REGEX]", "^[A-Za-z0-9]+\\[A-Za-z0-9\-]+$")
                        foreach ($group in $groups) { Log "  Group=$group" }
                        foreach ($add in $adds) { Log "  Add=$add" }

                        if(-not $whatIf.IsPresent) {
                            # add each item to the local group
				            $winNTcomputer = [ADSI]("WinNT://$ComputerName,computer")
                            foreach($group in $groups) {
                                if ([ADSI]::Exists("WinNT://./$group")) {
                                    $localGroup = $winNTcomputer.psbase.children.find($group)
                                    $members = @(net localgroup $group)

                                    # also keep track of the ones we've attempted to add (so we don't do it twice)
                                    $attemptedAdd = @()
				                    foreach ($add in $adds) {
                                        # only attempt to add it if it's not already there
                                        $name = $add
                                        $attemptedAdd += [array]$add
                                        if($attemptedAdd -inotcontains $name) {
                                            LogVerbose "Already attempted to add $name to $group"
                                        }
                                        elseif($members -inotcontains $name) {
                                            Try {
                                                $localGroup.Add([string]::Concat("WinNT://", $name.Replace("\","/")))
                                                Log "SUCCESS: Added $name to $group"
                                            }
                                            Catch {
                                                LogError "Failed adding $name to local group $group"
                                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                                Log ("  Exception Message: $($_.Exception.Message)")
                                                $actionSuccess = $False
                                            }
                                        }
                                        else {
                                            LogVerbose "$name is already in $group"
                                        }
				                    }
                                }
                                else {
                                    LogError "Invalid local group: $group"
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "Security.GetValidPassword" {
                        ValidateParamNames $action @("Account")
                        $accounts = GetActionParams $action "Account" $False @("[REGEX]", "^[A-Za-z0-9]+\\[A-Za-z0-9]+$")
                        foreach ($account in $accounts) { Log "  Account=$account" }

                        # keep a running list of passwords we need
                        $accounts | % { if(-not ($serviceAccountList -icontains $_)) { $serviceAccountList += [array]$_ } } 

                        if(-not $whatIf.IsPresent) {
                            foreach($account in $accounts) {
                                $getPassword = GetPassword $cachedPasswords $account
                                if($getPassword -eq "") {
                                    LogError "Unable to get a password for $account"
                                    $actionSuccess = $False
                                }
                                else {
                                    Log "SUCCESS: Cached password for $account"
                                }
                            }
                        }
                    }

                    "Powershell.EnableRemoteProcessExecution" {
                        ValidateParamNames $action @()

                        if(-not $whatIf.IsPresent) {
                            Try {
								#Test to see if PSRemoting is enabled. We need to skip the Enable-PSRemoting command if it is.
								#This is to stop this step from killing remote sessions when using -RemoteComputers
								$remotingEnabled = [bool](Test-WSMan -ComputerName 'localhost' -ErrorAction SilentlyContinue) 
								
								if($remotingEnabled){
									Log "SUCCESS: Enabled remote process execution of powershell scripts"
								}else{
									Enable-PSRemoting -Force | Out-Null
									Log "SUCCESS: Enabled remote process execution of powershell scripts"
								}
                            }
                            Catch {
                                LogError "Unable to enable powershell remote process execution"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Powershell.ExecuteCommand" {
                        ValidateParamNames $action @("Command","PSScript","PSFile","FailOnNonZeroReturnCode","FailOnReturnCodeList")
                        $commands = GetActionParams $action "Command" $False
                        $psScripts = GetActionParams $action "PSScript" $False
                        $psFiles = GetActionParams $action "PSFile" $False
                        $failOnNonZeroReturnCode = GetActionParam $action "FailOnNonZeroReturnCode" $False $False @("[BOOL]")
                        $failOnNonZeroReturnCode = (($failOnNonZeroReturnCode -ieq "true") -or ($failOnNonZeroReturnCode -eq $True))
                        $failOnReturnCodeList = GetActionParam $action "FailOnReturnCodeList" $False "" @("[REGEX]", "^[0-9,]+$")
                        foreach ($command in $commands) { Log "  Command=$(MaskPasswords $command)" }
                        foreach ($psScript in $psScripts) { Log "  PSScript=$(MaskPasswords $psScript)" }
                        foreach ($psFile in $psFiles) { Log "  PSFile=$psFile" }
                        Log "  FailOnNonZeroReturnCode=$failOnNonZeroReturnCode"
                        Log "  FailOnReturnCodeList=$failOnReturnCodeList"

                        if(-not $whatIf.IsPresent) {
                            foreach($command in $commands) {
                                $logCommand = MaskPasswords $command
                                Log "Executing: cmd /c $logCommand"
                                Try {
                                    if($logVerbose) {
                                        cmd /c $command
                                        $returnCode = $LASTEXITCODE
                                    }
                                    else {
                                        cmd /c $command | Out-Null
                                        $returnCode = $LASTEXITCODE
                                    }

                                    # are we failing on nonzero return code?
                                    if($failOnNonZeroReturnCode -and ($returnCode -ne "0")) {
                                        LogError "Executed: cmd /c $logCommand; exitcode = $returnCode"
                                        $actionSuccess = $False
                                    }
                                    # are we failing on a list of specific return codes?
                                    elseif (($failOnReturnCodeList -ne "") -and ($returnCode -in $failOnReturnCodeList.split(","))) {
                                        LogError "Executed: cmd /c $logCommand; exitcode = $returnCode"
                                        $actionSuccess = $False
                                    }
                                    else {
                                        Log "SUCCESS: Executed: cmd /c $logCommand; exitcode = $returnCode"
                                    }
                                }
                                Catch {
                                    LogError "Unable to execute command $logCommand"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                            foreach($psScript in $psScripts) {
                                $logPSScript = MaskPasswords $psScript
                                Log "Executing: powershell script expression $logPSScript"
                                Try {
                                    Invoke-Expression -Command "$psScript"
                                }
                                Catch {
                                    LogError "Unable to execute script $logPSScript"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                            foreach($psFile in $psFiles) {
                                Log "Executing: powershell file $psFile"
                                Try {
                                    # Invoke-Command -FilePath $psScript

                                    # are we failing on nonzero return code?
                                    if($failOnNonZeroReturnCode -and ($returnCode -ne "0")) {
                                        LogError "Executed: $psFile; exitcode = $returnCode"
                                        $actionSuccess = $False
                                    }
                                    # are we failing on a list of specific return codes?
                                    elseif (($failOnReturnCodeList -ne "") -and ($returnCode -in $failOnReturnCodeList.split(","))) {
                                        LogError "Executed: psFile; exitcode = $returnCode"
                                        $actionSuccess = $False
                                    }
                                    else {
                                        Log "SUCCESS: Executed: $psFile; exitcode = $returnCode"
                                    }
                                }
                                Catch {
                                    LogError "Unable to execute powershell file $psFile"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "Registry.AddKey" {
                        ValidateParamNames $action @("Hive","Key")
                        $hive = GetActionParam $action "Hive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $keys = GetActionParams $action "Key" $False
                        Log "  Hive=$hive"
                        foreach ($key in $keys) { Log "  Key=$key" }

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            foreach($key in $keys) {
                                if(-not (Test-Path ($hiveDrive+$key))) {
                                    Try {
                                        $keyPath = ($hiveDrive+$key).SubString(0, ($hiveDrive+$key).LastIndexOf('\'))
                                        $keyName = ($hiveDrive+$key).SubString($keyPath.Length+1)
                                        New-Item -Path $keyPath -Name $keyName -Force | Out-Null
                                        Log "SUCCESS: Created registry key $hive\$key"
                                    }
                                    Catch {
                                        LogError "Unable to create registry key $hive\$key"
                                        Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                        Log ("  Exception Message: $($_.Exception.Message)")
                                        $actionSuccess = $False
                                    }
                                }
                            }
                        }
                    }

                    "Registry.AddValue" {
                        ValidateParamNames $action @("Hive","Key","Value","Type","Data")
                        $hive = GetActionParam $action "Hive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $key = GetActionParam $action "Key" $True
                        $value = GetActionParam $action "Value" $True
                        $type = GetActionParam $action "Type" $False "REG_SZ" @("[ENUM]", "REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD")
                        $data = GetActionParam $action "Data" $True
                        Log "  Hive=$hive"
                        Log "  Key=$key"
                        Log "  Value=$value"
                        Log "  Type=$type"
                        Log "  Data=$data"

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            if ($type -ieq "REG_SZ") { $propertyType = "String" }
                            elseif ($type -ieq "REG_EXPAND_SZ") { $propertyType = "ExpandString" }
                            elseif ($type -ieq "REG_DWORD") { $propertyType = "DWord" }
                            elseif ($type -ieq "REG_QWORD") { $propertyType = "QWord" }
                            else { $propertyType = "Unknown" }

                            Try {
                                New-ItemProperty -Path ($hiveDrive+$key) -Name $value -Value $data -PropertyType $propertyType -Force | Out-Null
                                Log "SUCCESS: Set registry key value $hive\$key\$value to $type $data"
                            }
                            Catch {
                                LogError "Unable to set registry key value $hive\$key\$value to $type $data"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Registry.DeleteKey" {
                        ValidateParamNames $action @("Hive","Key")
                        $hive = GetActionParam $action "Hive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $keys = GetActionParams $action "Key" $False
                        Log "  Hive=$hive"
                        foreach ($key in $keys) { Log "  Key=$key" }

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            foreach($key in $keys) {
                                # for now commenting this out as mass deletion of a registry key is inherently dangerous
                                <#
                                Try {
                                    if(Test-Path -Path $hiveDrive+$key -PathType Container) {
                                        Remove-Item ($hiveDrive+$key) -Recurse
                                        Log "SUCCESS: Removed key $hive\$key and all subkeys and values"
                                    }
                                    else {
                                        LogVerbose "$hiveDrive+$key already does not exist"
                                    }
                                }
                                Catch {
                                    LogError "Unable to remove key $hive\$key"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                                #>
                            }
                        }
                    }

                    "Registry.DeleteValue" {
                        ValidateParamNames $action @("Hive","Key","Value")
                        $hive = GetActionParam $action "Hive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $key = GetActionParam $action "Key" $True
                        $value = GetActionParam $action "Value" $True
                        Log "  Hive=$hive"
                        Log "  Key=$key"
                        Log "  Value=$value"

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            Try {
                                # TODO: test for value existing needs fixing
                                if((Get-ItemProperty -Path ($hiveDrive+$key) -Name $value) -ne $null) {
                                    Remove-ItemProperty -Path ($hiveDrive+$key) -Name $value
                                    Log "SUCCESS: Removed registry key value $hive\$key\$value"
                                }
                                else {
                                    LogVerbose "$hiveDrive+$key already does not exist"
                                }
                            }
                            Catch {
                                LogError "Unable to remove registry key value $hive\$key\$value"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Registry.VerifyValue" {
                        ValidateParamNames $action @("Hive","Key","Value","Type","Data")
                        $hive = GetActionParam $action "Hive" $True "" @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $key = GetActionParam $action "Key" $True ""
                        $value = GetActionParam $action "Value" $True ""
                        $type = GetActionParam $action "Type" $False $null @("[ENUM]", "REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD")
                        $data = GetActionParam $action "Data" $True ""
                        Log "  Hive=$hive"
                        Log "  Key=$key"
                        Log "  Value=$value"
                        Log "  Type=$type"
                        Log "  Data=$data"

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            if ($type -ieq "REG_SZ") { $propertyType = "String" }
                            elseif ($type -ieq "REG_EXPAND_SZ") { $propertyType = "String" }
                            elseif ($type -ieq "REG_DWORD") { $propertyType = "Int32" }
                            elseif ($type -ieq "REG_QWORD") { $propertyType = "Int32" }
                            else { $propertyType = "Unknown" }

                            Try {
                                if (-not (Test-Path -Path ($hiveDrive+$key))) {
                                    LogError "Registry key $hive\$key is missing"
                                    $actionSuccess = $False
                                }
                                else {
                                    LogVerbose "Looking for value for $hiveDrive$key"
                                    $valueData = (Get-ItemProperty -Path ($hiveDrive+$key)).$value
                                    if ($valueData -eq $null) {
                                        LogError "Registry key value $hive\$key\$value is missing"
                                        $actionSuccess = $False
                                    }
                                    else {
                                        $valueType = (Get-ItemProperty -Path ($hiveDrive+$key)).$value.GetType().Name
                                        if($valueData -ne $data) {
                                            LogError "Registry key value $hive\$key\$value is $valueData and not $data"
                                            $actionSuccess = $False
                                        }
                                        elseif(($type -ne $null) -and ($valueType -ne $propertyType)) {
                                            LogError "Registry key value $hive\$key\$value is $data but type is $valueType and not $type"
                                            $actionSuccess = $False
                                        }
                                        else {
                                            Log "SUCCESS: Verified registry key value $hive\$key\$value"
                                        }
                                    }
                                }
                            }
                            Catch {
                                LogError "Unable to verify registry key value $hive\$key\$value is $type $data"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Registry.CopyKey" {
                        ValidateParamNames $action @("SourceHive","SourceKey","DestinationHive","DestinationKey","Recurse")
                        $sourceHive = GetActionParam $action "SourceHive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $sourceKey = GetActionParam $action "SourceKey" $True
                        $destinationHive = GetActionParam $action "DestinationHive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $destinationKey = GetActionParam $action "DestinationKey" $True
                        $recurse = GetActionParam $action "Recurse" $False $True @("[BOOL]")
                        $recurse = (($recurse -ieq "true") -or ($recurse -eq $True))
                        Log "  SourceHive=$sourceHive"
                        Log "  SourceKey=$sourceKey"
                        Log "  DestinationHive=$destinationHive"
                        Log "  DestinationKey=$destinationKey"
                        Log "  Recurse=$recurse"

                        if(-not $whatIf.IsPresent) {
                            $sourceHiveDrive = HiveDrive $sourceHive
                            $destinationHiveDrive = HiveDrive $destinationHive

                            <#if(-not (Test-Path ($hiveDrive+$key))) {
                                Try {
                                    $keyPath = ($hiveDrive+$key).SubString(0, ($hiveDrive+$key).LastIndexOf('\'))
                                    $keyName = ($hiveDrive+$key).SubString($keyPath.Length+1)
                                    New-Item -Path $keyPath -Name $keyName -Force | Out-Null
                                    Log "SUCCESS: Created registry key $hive\$key"
                                }
                                Catch {
                                    LogError "Unable to create registry key $hive\$key"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }#>
                        }
                    }

                    "Registry.AddPermission" {
                        ValidateParamNames $action @("Hive","Key","Object","Permission","Type","Inherit")
                        $hive = GetActionParam $action "Hive" $True $null @("[ENUM]", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU")
                        $key = GetActionParam $action "Key" $True
                        $object = GetActionParam $action "Object" $True
                        $permission = GetActionParam $action "Permission" $False "Read" @("[ENUM]", "Full", "Read")
                        $type = GetActionParam $action "Type" $False "Allow" @("[ENUM]", "Allow", "Deny")
                        $inherit = GetActionParam $action "Inherit" $False "KeyOnly" @("[ENUM]", "KeyOnly", "SubkeysOnly", "KeyAndSubkeys")
                        Log "  Hive=$hive"
                        Log "  Key=$key"
                        Log "  Object=$object"
                        Log "  Permission=$permission"
                        Log "  Type=$type"
                        Log "  Inherit=$inherit"

                        if(-not $whatIf.IsPresent) {
                            $hiveDrive = HiveDrive $hive

                            Try {
                                # calculate the parameter values base on the friendly parameter values
                                $registryRights = (@{"Full"="FullControl"; "Read"="ReadKey"})[$permission]
                                $propogationFlags = (@{"KeyOnly"="None"; "SubkeysOnly"="InheritOnly"; "KeyAndSubkeys"="None"})[$inherit]
                                $containerFlags = (@{"KeyOnly"="None"; "SubkeysOnly"="ContainerInherit"; "KeyAndSubkeys"="ContainerInherit"})[$inherit]

                                # set in the ACL
                                $acl = Get-Acl "$hiveDrive$key"
                                $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("$object", $registryRights, $containerFlags, $propogationFlags, $type)
                                $acl.SetAccessRule($rule)
                                $acl | Set-Acl -Path "$hiveDrive$key"
                                Log "SUCCESS: Added ($permission, $type) permission to $object in $hive\$key, $inherit"
                            }
                            Catch {
                                LogError "Unable to add ($permission, $type) permission to $object in $hive\$key, $inherit"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    
                    "Registry.IISLogging"{
                        ValidateParamNames $action @("Age","ErrorDelete","IsDisabled")
                        $age = GetActionParam $action "Age" $True
                        $errorDelete = GetActionParam $action "ErrorDelete" $False "True" @("[ENUM]", "True", "False")
                        $isDisabled = GetActionParam $action "IsDisabled" $False "" @("[ENUM]", "", "True", "False")
                        Log "  Age=$age"
                        Log "  ErrorDelete=$errorDelete"
                        Log "  IsDisabled=$isDisabled"

                        if(-not $whatIf.IsPresent) {
                            Try { 
                                $registryKey = "HKLM:\SOFTWARE\Progressive\IISLogsCleanup"
                                if(!(Test-Path -Path "$registryKey")) {
                                    #Create Registry Key if it does not already exist
                                    New-Item -Path "$registryKey" | Out-Null
                                }
                                
                                #String used to enable/disable IIS error logs deletion (Default = True)
                                RegistryKey.Value "$registryKey" "HTTPErr_Delete_Enabled" "$errorDelete"
                                #String used to disable IIS http logs deletion (Default = "")
                                RegistryKey.Value "$registryKey" "IsDisabled" "$isDisabled"
                                #String used to provide an example of site overrides
                                RegistryKey.Value "$registryKey" "Site_X_Override" ""
                                #Get collection of website ID's, will be used for site overrides
                                $siteIDCollection = (Get-WebSite).ID
                                foreach($id in $siteIDCollection) {
                                    #String used to provide file age override for http logs
                                    $stringName = "Site_"+$id+"_Override"
                                    RegistryKey.Value "$registryKey" "$stringName" "$age"
                                }
                            }
                            Catch {
                                LogError "Unable to registry Key/Strings for IIS Logs Override"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "System.SetEnvironmentVariable" {
                        ValidateParamNames $action @("Name","Value")
                        $name = GetActionParam $action "Name" $True
                        $value = GetActionParam $action "Value" $True
                        Log "  Name=$name"
                        Log "  Value=$value"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                [Environment]::SetEnvironmentVariable($name, $value, "Machine")
                                Log "SUCCESS: Set environment variable $name to $value"
                            }
                            Catch {
                                LogError "Unable to set environment variable $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "System.AddToPath" {
                        ValidateParamNames $action @("Folder")
                        $folders = GetActionParams $action "Folder" $False
                        foreach ($folder in $folders) { Log "  Folder=$folder" }

                        if(-not $whatIf.IsPresent) {
                            # read the current Path environment variable and split it by semicolon
                            $pathArray = ([Environment]::GetEnvironmentVariable("Path")).split(";")
                            foreach($folder in $folders) {
                                # if any are not already in the contents, add it
                                if ($pathArray -inotcontains $folder) { $pathArray += $folder }
                            }
                            Try {
                                [Environment]::SetEnvironmentVariable("Path", [string]::join(";", $pathArray), "Machine")
                                Log ("SUCCESS: Set PATH to $([string]::join(";", $pathArray))")
                            }
                            Catch {
                                LogError ("Unable to write new PATH environment variable with value $([string]::join(";", $pathArray))")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "EventLog.CreateEventLog" {
                        ValidateParamNames $action @("LogName","Source")
                        $logName = GetActionParam $action "LogName" $True
                        $sources = GetActionParams $action "Source" $False
                        Log "  LogName=$logName"
                        foreach ($source in $sources) { Log "  Source=$source" }

                        if(-not $whatIf.IsPresent) {
                            Try {
                                New-EventLog -LogName $logName -Source $source -ErrorAction Ignore
                                Log ("SUCCESS: Created new event log $source in $logName")
                            }
                            Catch {
                                LogError ("Unable to create new event log $source in $logName")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "EventLog.WriteEventLog" {
                        ValidateParamNames $action @("LogName","Source","EventID","Message","EntryType")
                        $logName = GetActionParam $action "LogName" $True
                        $source = GetActionParam $action "Source" $True
                        $eventID = GetActionParam $action "EventID" $True $null @("[REGEX]", "^[0-9]+$")
                        $message = GetActionParam $action "Message" $True
                        $entryType = GetActionParam $action "EntryType" $False "Information" @("[ENUM]","Error", "Warning", "Information", "SuccessAudit", "FailureAudit")
                        Log "  LogName=$logName"
                        Log "  Source=$source"
                        Log "  EventID=$eventID"
                        Log "  Message=$message"
                        Log "  EntryType=$entryType"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                Write-EventLog -LogName "$logName" -Source "$source" -EventID $eventID -Message "$message" -EntryType $entryType
                                Log ("SUCCESS: Wrote $entryType message ""$message"" to $logName log as event source $source, event ID $eventID")
                            }
                            Catch {
                                LogError ("Unable to write $entryType message ""$message"" to $logName log as event source $source, event ID $eventID")
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Service.CreateService" {
                        ValidateParamNames $action @("Name","Path","Description","DisplayName","Account","StartupType","AllowStop")
                        $name = GetActionParam $action "Name" $True
                        $path = GetActionParam $action "Path" $True
                        $description = GetActionParam $action "Description" $False ""
                        $displayName = GetActionParam $action "DisplayName" $False ""
                        $account = GetActionParam $action "Account" $False $null @("[REGEX]", "^[A-Za-z0-9 ]*[\\]?[A-Za-z0-9 ]+$")
                        $startupType = GetActionParam $action "StartupType" $False "Automatic" @("[ENUM]","Automatic","Manual","Disabled")
                        $allowStop = GetActionParam $action "AllowStop" $False $False @("[BOOL]")
                        $allowStop = ($allowStop -ieq $true) -or ($allowStop -ieq "true")
                        Log "  Name=$name"
                        Log "  Path=$path"
                        Log "  Description=$description"
                        Log "  DisplayName=$displayName"
                        Log "  Account=$account"
                        Log "  StartupType=$startupType"
                        Log "  AllowStop=$allowStop"

                        # build list of referenced service accounts
                        if(-not(($account -eq $null) -or ($account -ieq "NT AUTHORITY\LocalSystem") -or ($account -ieq "LocalSystem"))) {
                            if(-not ($serviceAccountList -icontains $account)) {
                                $serviceAccountList += [array]$account
                            }
                        }

                        if(-not $whatIf.IsPresent) {
                            Try {
                                # if the service exists, see if the important stuff agrees
                                $serviceObject = (Get-WmiObject -Query "Select * from Win32_Service Where Name='$name'")

                                if($serviceObject -ne $Null) {
                                    LogVerbose "Service $name already exists"

                                    # forcibly set path & credentials
                                    if(($account -eq $null) -or ($account -ieq "NT AUTHORITY\LocalSystem") -or ($account -ieq "LocalSystem")) {
                                        $serviceObject.Change($null, $path, $null, $null, $null, $false, $null, $null, $null, $null, $null) | Out-Null
                                    }
                                    elseif($account -ieq "Network Service") {
                                        $serviceObject.Change($null, $path, $null, $null, $null, $false, "Network Service", "", $null, $null, $null) | Out-Null
                                    }
                                    else {
                                        $getPassword = GetPassword $cachedPasswords $account
                                        if($getPassword -ne "") {
                                            $serviceObject.Change($null, $path, $null, $null, $null, $false, $account, $getPassword, $null, $null, $null) | Out-Null
                                        }
                                    }
                                }
                                # else try to create the service
                                else {
                                    if(($account -eq $null) -or ($account -ieq "NT AUTHORITY\LocalSystem") -or ($account -ieq "LocalSystem")) {
                                        LogVerbose "Creating new service $name running $path"
                                        $service = New-Service -Name "$name" -BinaryPathName "$path"
                                    }
                                    else {
                                        $getPassword = GetPassword $cachedPasswords $account
                                        if($getPassword -ne "") {
                                            LogVerbose "Creating secure credentials object from the account and password"
                                            $securePassword = ConvertTo-SecureString $getPassword -AsPlainText -Force
                                            $credentials = New-Object System.Management.Automation.PSCredential ($account, $securePassword)

                                            LogVerbose "Creating new service $name running $path using $account"
                                            $service = New-Service -Name "$name" -BinaryPathName "$path" -Credential $credentials
                                        }
                                    }
                                }
                                if($description -ne "") {
                                    LogVerbose "Setting description=$description"
                                    Set-Service -Name "$name" -Description "$description"
                                    Log "Set description=$description"
                                }
                                if($displayName -ne "") {
                                    LogVerbose "Setting display name=$displayName"
                                    Set-Service -Name "$name" -DisplayName "$displayName"
                                    Log "Set display name=$displayName"
                                }
                                if($startupType -ne "") {
                                    Log "Setting startup type=$startupType"
                                    Set-Service -Name "$name" -StartupType $startupType
                                    Log "Set startup type=$startupType"
                                }
                                Log "SUCCESS: Created new service $name"
                            }
                            Catch {
                                LogError "Unable to create service $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Service.SetStartupType" {
                        ValidateParamNames $action @("Name","StartupType")
                        $name = GetActionParam $action "Name" $True
                        $startupType = GetActionParam $action "StartupType" $True "Automatic" @("[ENUM]","Automatic","Manual","Disabled")
                        Log "  Name=$name"
                        Log "  StartupType=$startupType"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if(($service = Get-Service -Name "$name") -eq $null) {
                                    LogError "Unable to set service $name startup type; Service does not exist"
                                    $actionSuccess = $False
                                }
                                else {
                                    Set-Service -Name "$name" -StartupType $startupType
                                    Log "SUCCESS: Set service $name startup type to $startupType"
                                }
                            }
                            Catch {
                                LogError "Unable to set service $name startup type"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Service.StartService" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                Service.StatusChange "Start" "$name"
                            }
                            Catch {
                                LogError "Unable to start service $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Service.StopService" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                Service.StatusChange "Stop" "$name"
                            }
                            Catch {
                                LogError "Unable to stop service $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Service.RestartService" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                Service.StatusChange "Restart" "$name"
                            }
                            Catch {
                                LogError "Unable to restart service $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "TaskManager.CreateTask" {
                        ValidateParamNames $action @("Name","Description","Action","ArgumentList","TriggerOnce","TriggerDaily","TriggerWeekly","UserName","EnableNew")
                        $name = GetActionParam $action "Name" $True
                        $description = GetActionParam $action "Description" $False "none"
                        $taskActions = GetActionParams $action "Action" $True
                        $triggerOnces = GetActionParams $action "TriggerOnce" $False
                        $triggerDailys = GetActionParams $action "TriggerDaily" $False
                        $triggerWeeklys = GetActionParams $action "TriggerWeekly" $False
                        $userName = GetActionParam $action "UserName" $False $null @("[REGEX]", "^[A-Za-z0-9 ]+\\[A-Za-z0-9]+$")
                        $enableNew = GetActionParam $action "EnableNew" $False "" @("[BOOL]")
                        $enableNew = (($enableNew -ieq $true) -or ($enableNew -ieq "true"))
                        Log "  Name=$name"
                        Log "  Description=$description"
                        foreach($taskAction in $taskActions) { Log "  Action=$taskAction" }
                        foreach($triggerOnce in $triggerOnces) { Log "  TriggerOnce=$triggerOnce" }
                        foreach($triggerDaily in $triggerDailys) { Log "  TriggerDaily=$triggerDaily" }
                        foreach($triggerWeekly in $triggerWeeklys) { Log "  TriggerWeekly=$triggerWeekly" }
                        Log "  UserName=$userName"
                        Log "  EnableNew=$enableNew"

                        # assume it's new and we're using the "enable if new" setting - if it exists, we'll override with the current setting
                        $enable = $enableNew

                        # keep a running list of passwords we need
                        if(-not $userName.ToUpper().StartsWith("NT AUTHORITY\")) {
                            if(-not ($serviceAccountList -icontains $userName)) { $serviceAccountList += [array]$userName }
                        }

                        if(-not (PSCmdletAvailable "New-ScheduledTask")) {
                            LogError "Unable to attempt action; New-ScheduledTask cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # task already exists - deleting it
                                $existingTask = (Get-ScheduledTask -TaskName "$name" -ErrorAction Ignore)
                                if($existingTask -ne $null) {
                                    # override setting to (re)enable it
                                    $enable = -not ($existingTask.State -ieq "disabled")

                                    # now wipe out existing task
                                    LogVerbose "Task $name exists as enabled=$enable, unregistering it first and then creating a new one"
                                    Unregister-ScheduledTask -TaskName "$name" -Confirm:$false
                                }
                                else {
                                    LogVerbose "Task $name is new - setting enabled to $enable"
                                }

                                # Define the action with New-ScheduledTaskAction
                                $schedTaskActions = @()
                                foreach($taskAction in $taskActions) {
                                    # accepts either of:
                                    #    <Param Name='Action'>pathyourEXE</Param>
                                    #    <Param Name='Action'>Path=pathtojob;Parameters=params</Param>
                                    if($taskAction.Contains(";")) {
                                        # e.g. Path=pathtojob;Parameters=params
                                        LogVerbose("Parsing $taskAction into Path and Parameters")
                                        $actionKeyValues = KeyValuePairs "$taskAction" ";" "=" "Path,Parameters"
                                        $path = GetKeyValue $actionKeyValues "Path" $taskAction
                                        $argumentList = GetKeyValue $actionKeyValues "Parameters" ""
                                    }
                                    else {
                                        LogVerbose("Setting path to $taskAction")
                                        $path = $taskAction
                                        $argumentList = ""
                                    }

                                    if($argumentList -eq "") {
                                        LogVerbose("Creating scheduled task action to execute $path")
                                        $schedTaskActions += New-ScheduledTaskAction -Execute "$path"
                                    }
                                    else {
                                        LogVerbose("Creating scheduled task action to execute $path with parameters $argumentList")
                                        $schedTaskActions += New-ScheduledTaskAction -Execute "$path" -Argument "$argumentList"
                                    }
                                }

                                # Creating the task trigger with New-ScheduledTaskTrigger
                                $triggers = @()
                                foreach($triggerOnce in $triggerOnces) {
                                    # e.g. DateTime=03:00; RepetitionInterval=5; RepetitionDuration=720
                                    LogVerbose("Parsing $triggerOnce into Key,Value pairs")
                                    $triggerKeyValues = KeyValuePairs "$triggerOnce" ";" "=" "DateTime,RepetitionInterval,RepetitionDuration"
                                    $time = GetKeyValue $triggerKeyValues "DateTime" $null
                                    if($time -eq $null) { $time = Get-Date }
                                    $interval = GetKeyValue $triggerKeyValues "RepetitionInterval" $null
                                    $duration = GetKeyValue $triggerKeyValues "RepetitionDuration" $null
                                    if($duration -eq $null) { $duration = ([System.TimeSpan]::MaxValue) } else { $duration = (New-TimeSpan -Minutes ([int]$duration)) }

                                    if($interval -eq $null) {
                                        LogVerbose "Adding a one time trigger at $time"
                                        $triggers += New-ScheduledTaskTrigger -Once -At "$time"
                                    }
                                    else {
                                        LogVerbose "Adding a one time trigger at $time repeating every $interval minutes for a duration of $duration"
                                        $triggers += New-ScheduledTaskTrigger -Once -At "$time" -RepetitionInterval (New-TimeSpan -Minutes ([int]$interval)) -RepetitionDuration $duration
                                    }
                                }
                                foreach($triggerDaily in $triggerDailys) {
                                    # e.g. DateTime=03:00; DaysInterval=2
                                    LogVerbose("Parsing $triggerDaily into Key,Value pairs")
                                    $triggerKeyValues = KeyValuePairs "$triggerDaily" ";" "=" "DateTime,DaysInterval"
                                    $time = GetKeyValue $triggerKeyValues "DateTime" "00:00"
                                    $interval = GetKeyValue $triggerKeyValues "DaysInterval" "1"

                                    LogVerbose "Adding a daily trigger at $time repeating every $interval day(s)"
                                    $triggers += New-ScheduledTaskTrigger -Daily -At "$time" -DaysInterval $interval
                                }
                                foreach($triggerWeekly in $triggerWeeklys) {
                                    # e.g. daysofweek=Sunday,Saturday; datetime=03:00; weeksinterval=2
                                    LogVerbose("Parsing $triggerWeekly into Key,Value pairs")
                                    $triggerKeyValues = KeyValuePairs "$triggerWeekly" ";" "=" "DateTime,DaysOfWeek,WeeksInterval"
                                    $time = GetKeyValue $triggerKeyValues "DateTime" "00:00"
                                    $dow = GetKeyValue $triggerKeyValues "DaysOfWeek" "Sunday,Monday,Tuesday,Wednesday,Thursday,Friday,Saturday"
                                    $interval = GetKeyValue $triggerKeyValues "WeeksInterval" "1"

                                    LogVerbose "Adding a weekly trigger at $time repeating on days $dow every $interval week(s)"
                                    $triggers += New-ScheduledTaskTrigger -Weekly -At "$time" -DaysOfWeek $dow -WeeksInterval $interval
                                }

                                # Creating the scheduled task with New-ScheduledTask
                                LogVerbose "Create a new task object with the above triggers"
                                $task = New-ScheduledTask -Action $schedTaskActions -Trigger $triggers -Settings (New-ScheduledTaskSettingsSet)

                                # Registering the scheduled task with Register-ScheduledTask
                                LogVerbose "Registering the task using $userName"
                                if($userName.ToUpper().StartsWith("NT AUTHORITY\")) {
                                    $task | Register-ScheduledTask -TaskName "$name" -User "$userName" | Out-Null
                                }
                                else {
                                    $password = GetPassword $cachedPasswords $userName
                                    $task | Register-ScheduledTask -TaskName "$name" -User "$userName" -Password "$password" | Out-Null
                                }

                                # are we explicitly enabling or disabling the task?
                                if($enable -ne $null) {
                                    if($enable) {
                                        LogVerbose "Enabling the task"
                                        Enable-ScheduledTask -TaskName "$name" | Out-Null
                                    }
                                    else {
                                        LogVerbose "Disabling the task"
                                        Disable-ScheduledTask -TaskName "$name" | Out-Null
                                    }
                                }

                                Log "SUCCESS: Created task $name"
                            }
                            Catch {
                                LogError "Unable to create scheduled task $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "TaskManager.DeleteTask" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Unregister-ScheduledTask")) {
                            LogError "Unable to attempt action; Unregister-ScheduledTask cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-ScheduledTask -TaskName "$name" -ErrorAction Ignore) -ne $null) {
                                    Unregister-ScheduledTask -TaskName "$name" -Confirm:$false
                                }
                                Log "SUCCESS: Deleted task $name"
                            }
                            Catch {
                                LogError "Unable to delete scheduled task $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "TaskManager.EnableTask" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Enable-ScheduledTask")) {
                            LogError "Unable to attempt action; Enable-ScheduledTask cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-ScheduledTask -TaskName "$name" -ErrorAction Ignore) -ne $null) {
                                    Enable-ScheduledTask -TaskName "$name" | Out-Null
                                }
                                Log "SUCCESS: Enabled task $name"
                            }
                            Catch {
                                LogError "Unable to enable scheduled task $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "TaskManager.DisableTask" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Disable-ScheduledTask")) {
                            LogError "Unable to attempt action; Disable-ScheduledTask cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-ScheduledTask -TaskName "$name" -ErrorAction Ignore) -ne $null) {
                                    Disable-ScheduledTask -TaskName "$name" | Out-Null
                                }
                                Log "SUCCESS: Disabled task $name"
                            }
                            Catch {
                                LogError "Unable to disable scheduled task $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.CreateGroup" {
                        ValidateParamNames $action @("Group","Type")
                        $group = GetActionParam $action "Group" $True
                        $type = GetActionParam $action "Type" $False "Unknown" @("[ENUM]","Unknown")  # will add more types later
                        Log "  Group=$group"
                        Log "  Type=$type"

                        if(-not (PSCmdletAvailable "Add-ClusterGroup")) {
                            LogError "Unable to attempt action; Add-ClusterGroup cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if(-not ((Get-ClusterGroup).Name -icontains "$group")) {
                                    LogVerbose "Adding a new cluster group $group of type $type"
                                    Add-ClusterGroup -Name "$group" -GroupType "$type" | Out-Null
                                }
                                else {
                                    LogVerbose "Cluster group $group already exists"
                                }
                                Log "SUCCESS: Created cluster group $group"
                            }
                            Catch {
                                LogError "Unable to create cluster group $group"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.AddServiceToGroup" {
                        ValidateParamNames $action @("Group","Service")
                        $group = GetActionParam $action "Group" $True
                        $service = GetActionParam $action "Service" $True
                        Log "  Group=$group"
                        Log "  Service=$service"

                        if(-not (PSCmdletAvailable "Add-ClusterResource")) {
                            LogError "Unable to attempt action; Add-ClusterResource cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # if the resource is not clustered go ahead and add it to the group
                                if(-not ((Get-ClusterResource).Name -contains "$service")) {
                                    LogVerbose "Adding service $service to group $group as a 'generic service'"
                                    Add-ClusterResource -Group "$group" -ResourceType "Generic Service" -Name "$service" | Out-Null
                                    Log "SUCCESS: Service $service belongs to cluster group $group"
                                }
                                else {
                                    # get the clustered resource
                                    $resource = Get-ClusterResource -Name "$service"
                                    # if that resource is already on that group as a Generic Service, it's success
                                    if(($resource.OwnerGroup.Name -ieq "$group") -and ($resource.ResourceType.Name -ieq "Generic Service")) {
                                        LogVerbose "Service $service is already in group $group as a 'generic service'"
                                        Log "SUCCESS: Service $service belongs to cluster group $group"
                                    }
                                    # otherwise you can't add
                                    else {
                                        LogError "Unable to add service $service to $group.  $service is already a $($resource.ResourceType.Name) resource on group $($resource.OwnerGroup.Name)"
                                        $actionSuccess = $False
                                    }
                                }
                            }
                            Catch {
                                LogError "Unable to add service $service to $group"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.MoveGroup" {
                        ValidateParamNames $action @("Group","Node")
                        $group = GetActionParam $action "Group" $True
                        $node = GetActionParam $action "Node" $True
                        Log "  Group=$group"
                        Log "  Node=$node"

                        if(-not (PSCmdletAvailable "Move-ClusterGroup")) {
                            LogError "Unable to attempt action; Move-ClusterGroup cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                Move-ClusterGroup -Name "$group" -Node "$node"
                                Log "SUCCESS: Moved group $group to node $node"
                            }
                            Catch {
                                LogError "Unable to move group $group to node $node"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.StartGroup" {
                        ValidateParamNames $action @("Group")
                        $group = GetActionParam $action "Group" $True
                        Log "  Group=$group"

                        if(-not (PSCmdletAvailable "Start-ClusterGroup")) {
                            LogError "Unable to attempt action; Start-ClusterGroup cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                Start-ClusterGroup -Name "$group" | Out-Null
                                Log "SUCCESS: Started group $group"
                            }
                            Catch {
                                LogError "Unable to start group $group"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.StopGroup" {
                        ValidateParamNames $action @("Group")
                        $group = GetActionParam $action "Group" $True
                        Log "  Group=$group"

                        if(-not (PSCmdletAvailable "Stop-ClusterGroup")) {
                            LogError "Unable to attempt action; Stop-ClusterGroup cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                Stop-ClusterGroup -Name "$group" | Out-Null
                                Log "SUCCESS: Stopped group $group"
                            }
                            Catch {
                                LogError "Unable to stop group $group"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Cluster.StartResource" {
                        ValidateParamNames $action @("Resource")
                        $resources = GetActionParams $action "Resource" $True
                        foreach($resource in $resources) { Log "  Resource=$resource" }

                        if(-not (PSCmdletAvailable "Start-ClusterResource")) {
                            LogError "Unable to attempt action; Start-ClusterResource cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($resource in $resources) {
                                Try {
                                    Start-ClusterResource -Name "$resource" | Out-Null
                                    Log "SUCCESS: Started resource $resource"
                                }
                                Catch {
                                    LogError "Unable to start resource $resource"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "Cluster.StopResource" {
                        ValidateParamNames $action @("Resource")
                        $resources = GetActionParams $action "Resource" $True
                        foreach($resource in $resources) { Log "  Resource=$resource" }

                        if(-not (PSCmdletAvailable "Stop-ClusterResource")) {
                            LogError "Unable to attempt action; Stop-ClusterResource cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            foreach($resource in $resources) {
                                Try {
                                    Stop-ClusterResource -Name "$resource" | Out-Null
                                    Log "SUCCESS: Stopped resource $resource"
                                }
                                Catch {
                                    LogError "Unable to stop resource $resource"
                                    Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                    Log ("  Exception Message: $($_.Exception.Message)")
                                    $actionSuccess = $False
                                }
                            }
                        }
                    }

                    "System.VerifyOSHardware" {
                        ValidateParamNames $action @("OS","Processors","Memory","DriveSize")
                        $OS = GetActionParam $action "OS" $False $null @("[ENUM]","Windows 7","2008 Standard","2008 R2 Standard","2008 Enterprise","2008 R2 Enterprise","2012 R2 Standard")
                        $processors = GetActionParam $action "Processors" $False $null @("[REGEX]","^[1-9]+[0-9]*$")
                        $memory = GetActionParam $action "Memory" $False $null @("[REGEX]","^[1-9]+[0-9]*$")
                        $driveSizes = GetActionParams $action "DriveSize" $False @("[REGEX]","^[C-Zc-z]=[1-9]+[0-9]*$")
                        Log "  OS=$OS"
                        Log "  Processors=$processors"
                        Log "  Memory=$memory"
                        foreach($driveSize in $driveSizes) { Log "  DriveSize=$driveSize" }

                        if(-not $whatIf.IsPresent) {
                            Try {
                                if($OS -ne $null) {
                                    $wmiOS = (Get-WmiObject Win32_OperatingSystem).Caption.Trim()
                                    switch ($OS) {
                                        "Windows 7" {
                                            if(-not $wmiOS.Contains("Windows 7")) {
                                                LogError "OperatingSystem Invalid; \"$OS\" desired and $wmiOS present"
                                            }
                                        }
                                        {$_ -in "2008 Standard","2008 R2 Standard","2008 Enterprise","2008 R2 Enterprise","2012 R2 Standard"} {
                                            if(-not $wmiOS.EndsWith($_)) {
                                                LogError "OperatingSystem Invalid; ""$OS"" desired and [$wmiOS] present"
                                            }
                                            else {
                                                Log "Verified OS $OS"
                                            }
                                        }
                                    }
                                }
                                if($processors -ne $null) {
                                    $processorCount = (Get-WmiObject –class Win32_processor).Count
                                    if($processorCount -eq $null) { $processorCount = 1 }
                                    if($processors -ne $processorCount) {
                                        LogError "Processor Count Invalid; $processors desired and $processorCount present"
                                        $actionSuccess = $False
                                    }
                                    else {
                                        Log "Verified processor count $processors"
                                    }
                                }
                                if($memory -ne $null) {
                                    $wmiVMSizeGB = ((Get-WmiObject Win32_OperatingSystem).TotalVirtualMemorySize) / 1024.0 / 1024.0
                                    if(([math]::abs(($wmiVMSizeGB - [int]$memory) / [int]$memory) * 100) -gt 1.0) {
                                        LogError ("Memory Invalid; $memory GB desired and $([math]::Round($wmiVMSizeGB, 1)) GB present")
                                        $actionSuccess = $False
                                    }
                                    else {
                                        Log "Verified memory $memory GB"
                                    }
                                }
                                foreach($driveSize in $driveSizes) {
                                    $drvLetter = ($driveSize.Split('='))[0]
                                    $drvSize = [int]((($driveSize.Split('='))[1]))
                                    $drvInfo = Get-PSDrive -Name $drvLetter
                                    if($drvInfo -eq $null) {
                                        LogError ("$($drvLetter): Drive size invalid; Drive does not exist")
                                        $actionSuccess = $False
                                    }
                                    else {
                                        $drvTotalSize = ($drvInfo.Free + $drvInfo.Used) / 1024.0 / 1024.0 / 1024.0
                                        if(([math]::abs(($drvTotalSize - [int]$drvSize) / [int]$drvSize) * 100) -gt 1.0) {
                                            LogError ("$($drvLetter): Drive size invalid; $drvSize GB desired and $([math]::Round($drvTotalSize, 1)) GB present")
                                            $actionSuccess = $False
                                        }
                                        else {
                                            Log ("Verified $($drvLetter): drive size $drvSize GB")
                                        }
                                    }
                                }
                            }
                            Catch {
                                LogError "Unable to verify OS and/or hardware; Failed to retrieve data"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Server.AddWindowsFeature" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Add-WindowsFeature")) {
                            LogError "Unable to attempt action; Add-WindowsFeature cmdlet not not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-WindowsFeature -Name "$name") -eq $null) {
                                    LogError "Unable to add Windows Feature $name - invalid feature name"
                                    $actionSuccess = $False
                                }
                                elseif((Get-WindowsFeature -Name "$name").Installed -ieq $true) {
                                    LogVerbose "Windows Feature $name is already installed"
                                }
                                else {
                                    Add-WindowsFeature -Name "$name" | Out-Null
                                    Log ("SUCCESS: Added Windows Feature $name")
                                }
                            }
                            Catch {
                                LogError "Unable to add Windows Feature $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Server.RemoveWindowsFeature" {
                        ValidateParamNames $action @("Name")
                        $name = GetActionParam $action "Name" $True
                        Log "  Name=$name"

                        if(-not (PSCmdletAvailable "Remove-WindowsFeature")) {
                            LogError "Unable to attempt action; Remove-WindowsFeature cmdlet not not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-WindowsFeature -Name "$name") -eq $null) {
                                    LogError "Unable to remove Windows Feature $name - invalid feature name"
                                    $actionSuccess = $False
                                }
                                elseif((Get-WindowsFeature -Name "$name").Installed -ieq $false) {
                                    LogVerbose "Windows Feature $name is already not installed"
                                }
                                else {
                                    Remove-WindowsFeature -Name "$name" | Out-Null
                                    Log ("SUCCESS: Removed Windows Feature $name")
                                }
                            }
                            Catch {
                                LogError "Unable to remove Windows Feature $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Server.VerifyWindowsFeature" {
                        ValidateParamNames $action @("Name","Installed")
                        $name = GetActionParam $action "Name" $True
                        $installed = GetActionParam $action "Installed" $False $True @("[BOOL]")
                        $installed = (($installed -ieq "true") -or ($installed -eq $True))
                        Log "  Name=$name"
                        Log "  Installed=$installed"

                        if(-not (PSCmdletAvailable "Get-WindowsFeature")) {
                            LogError "Unable to attempt action; Get-WindowsFeature cmdlet not not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                if((Get-WindowsFeature -Name "$name") -eq $null) {
                                    LogError "Unable to verify Windows Feature $name - invalid feature name"
                                    $actionSuccess = $False
                                }
                                # is it the desired installed state?
                                elseif((Get-WindowsFeature -Name "$name").Installed -eq $installed) {
                                    Log "SUCCESS: Windows Feature $name installed = $installed"
                                }
                                else {
                                    LogError "Windows Feature $name installed != $installed"
                                    $actionSuccess = $False
                                }
                            }
                            Catch {
                                LogError "Unable to remove Windows Feature $name"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "XML.Poke" {
                        ValidateParamNames $action @("File","XPath","Value","MinOccur","MaxOccur")
                        $file = GetActionParam $action "File" $True
                        $XPath = GetActionParam $action "XPath" $True
                        $value = GetActionParam $action "Value" $True
                        $minOccur = GetActionParam $action "MinOccur" $False 1 @("[REGEX]","^[0-9]*$")
                        $maxOccur = GetActionParam $action "MaxOccur" $False "" @("[REGEX]","^[0-9]*$")
                        Log "  File=$file"
                        Log "  XPath=$XPath"
                        Log "  Value=$value"
                        Log "  minOccur=$minOccur"
                        Log "  maxOccur=$maxOccur"

                        if(-not $whatIf.IsPresent) {
                            Try {
                                # load XML
                                LogVerbose "Loading $file in as XML data"
                                [xml]$pokeXML = Get-Content $file

                                # select nodes with XPath
                                $nodes = $pokeXML.SelectNodes($XPath)
                                LogVerbose "Found $($nodes.Count) occurrence(s) of $XPath"

                                # check against min if present
                                if($minOccur -ne "") {
                                    if($nodes.Count -lt [int]$minOccur) {
                                        LogError "Failed to poke value - $($nodes.Count) occurrence(s) below minimum $minOccur required"
                                        $actionSuccess = $False
                                    }
                                }

                                # check against max if present
                                if($maxOccur -ne "") {
                                    if($nodes.Count -gt [int]$maxOccur) {
                                        LogError "Failed to poke value - $($nodes.Count) occurrence(s) above maximum $minOccur allowed"
                                        $actionSuccess = $False
                                    }
                                }

                                # set each node to the new value
                                if($actionSuccess) {
                                    $modified = $false
                                    foreach($node in $nodes) {
                                        if($node -is [System.Xml.XmlAttribute])
                                        {
                                            if($node.Value -ne $value) {
                                                LogVerbose "Current value is $($node.Value) - updating to $value"
                                                $modified = $true
                                                $node.Value = $value
                                            }
                                            else {
                                                LogVerbose "Current value is already $($node.Value)"
                                            }
                                        }
                                        else {
                                            if($node.InnerText -ne $value) {
                                                LogVerbose "Current value is $($node.InnerText) - updating to $value"
                                                $modified = $true
                                                $node.InnerText = $value
                                            }
                                            else {
                                                LogVerbose "Current value is already $($node.InnerText)"
                                            }
                                        }
                                    }

                                    if($modified) {
                                        # save the new XML
                                        LogVerbose "Writing XML data to $file"
                                        $pokeXML.Save($file)
                                    }

                                    Log "SUCCESS: Updated $($nodes.Count) occurrences of expression to $value"
                                }
                            }
                            Catch {
                                LogError "Unable to poke values into $file"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    "Model3API.AddSwaggerServer" {
                        ValidateParamNames $action @("Site","Version","PoolUserName","PoolFramework","AnonymousAuth","AnonymousAuthUserName","WindowsAuth","SwaggerFiles","HostHeader")
                        $site = GetActionParam $action "Site" $True
                        $version = GetActionParam $action "Version" $False "1.2" @("[ENUM]", "1.2", "2.0")
                        $poolUserName = GetActionParam $action "PoolUserName" $True $null @("[REGEX]", "^[A-Za-z0-9]+\\[A-Za-z0-9]+$")
                        $poolFramework = GetActionParam $action "PoolFramework" $False "v4.0" @("[ENUM]", "v2.0", "v4.0")
                        $anonymousAuth = GetActionParam $action "AnonymousAuth" $False $null @("[BOOL]")
                        $anonymousAuthUserName = GetActionParam $action "AnonymousAuthUserName" $False $null
                        $windowsAuth = GetActionParam $action "WindowsAuth" $False $null @("[BOOL]")
                        $swaggerFiles = GetActionParam $action "SwaggerFiles" $False
                        $hostHeader = GetActionParam $action "HostHeader" $False
                        Log "  Site=$site"
                        Log "  Version=$version"
                        Log "  PoolUserName=$poolUserName"
                        Log "  PoolFramework=$poolFramework"
                        Log "  AnonymousAuth=$anonymousAuth"
                        Log "  AnonymousAuthUserName=$anonymousAuthUserName"
                        Log "  WindowsAuth=$windowsAuth"
                        Log "  SwaggerFiles=$swaggerFiles"
                        Log "  HostHeader=$hostHeader"

                        # build list of referenced service accounts
                        if(-not ($serviceAccountList -icontains $poolUserName)) {
                            $serviceAccountList += [array]$poolUserName
                        }

                        if(-not (PSCmdletAvailable "New-WebApplication")) {
                            LogError "Unable to attempt action; New-WebApplication cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                # Create an app pool using $ZID
                                $swaggerServerAppPool = "SwaggerServer-$site"
                                Log "Creating app pool $swaggerServerAppPool for SwaggerServer application"
                                if(-not (Test-Path "IIS:\AppPools\$swaggerServerAppPool")) {
                                    New-WebAppPool -Name "$swaggerServerAppPool" | Out-Null
                                }		
                                Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name ManagedRuntimeVersion -Value "$poolFramework"
                                Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name ManagedPipelineMode -Value 0
                                Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name ProcessModel.IdentityType -Value 3
                                Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name AutoStart -Value $True

                                $pool = Get-Item "IIS:\AppPools\$swaggerServerAppPool"
                                $pool.processModel.userName = "$poolUserName"
                                $pool.processModel.password = "$(GetPassword $cachedPasswords $poolUserName)"
                                $pool | Set-Item

                                $appFolder = "SwaggerServer"
                                if($version -eq "2.0") { $appFolder = "SwaggerServer20" }
                                $appName = $appFolder

                                # Create an app under $Site
                                Log "Creating site $site app $appName using d:\inetpub\vserver\$Site\$appFolder and app pool $swaggerServerAppPool"
                                if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder" -PathType Container)) {
                                    New-Item -Path "d:\inetpub\vserver\$Site\$appFolder" -ItemType Directory | Out-Null
                                }
                                if((Get-WebApplication -Site "$Site" -Name "$appName") -eq $null) {
                                    New-WebApplication -Site "$Site" -Name "$appName" -PhysicalPath "d:\inetpub\vserver\$Site\$appFolder" -ApplicationPool "$swaggerServerAppPool" | Out-Null
                                }
                                else {
                                    # force the application pool & physical folder
                                    Set-ItemProperty "IIS:\Sites\$site\$appName" -Name ApplicationPool "$swaggerServerAppPool"
                                    Set-ItemProperty "IIS:\Sites\$site\$appName" -Name physicalPath -Value "d:\inetpub\vserver\$Site\$appFolder"
                                }

                                # set $anonymousAuth, $windowsAuth, $formsAuth
                                Log "Setting authentication settings for site $site app $appName"
                                if($anonymousAuth -eq "") {
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$appName" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled
                                }
                                elseif($anonymousAuth -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$appName" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value "$anonymousAuth"
                                }
                                if($anonymousAuthUserName -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$appName" -Filter system.webServer/security/authentication/anonymousauthentication -Name userName -Value "$anonymousAuthUserName"
                                }
                                if($windowsAuth -eq "") {
                                    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$appName" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                }
                                elseif($windowsAuth -ne $null) {
                                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$appName" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value "$windowsAuth"
                                }

                                Log "Creating physical path d:\inetpub\vserver\$Site\$appFolder\api-docs"
                                if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\api-docs" -PathType Container)) {
                                    New-Item -Path "d:\inetpub\vserver\$Site\$appFolder\api-docs" -ItemType Directory | Out-Null
                                }
                                # for 1.2 create an app /SwaggerServer/api-docs under $Site using app pool SwaggerServer-$Site and folder d:\inetpub\vserver\$Site\SwaggerServer\api-docs
                                if($version -eq "1.2") {
                                    Log "Creating site $site app $appName/api-docs using d:\inetpub\vserver\$Site\$appFolder\api-docs and app pool $swaggerServerAppPool"
                                    if((Get-WebApplication -Site "$Site" -Name "$appName/api-docs") -eq $null) {
                                        New-WebApplication -Site "$Site" -Name "$appName/api-docs" -PhysicalPath "d:\inetpub\vserver\$Site\$appFolder\api-docs" -ApplicationPool "$swaggerServerAppPool" | Out-Null
                                    }
                                    else {
	                                    # force the application pool & physical folder
	                                    Set-ItemProperty "IIS:\Sites\$site\$appName\api-docs" -Name ApplicationPool "$swaggerServerAppPool"
	                                    Set-ItemProperty "IIS:\Sites\$site\$appName\api-docs" -Name physicalPath -Value "d:\inetpub\vserver\$Site\$appFolder\api-docs"
                                    }
                                }

                                # Copy in SwaggerServer files
                                if($swaggerFiles -eq $null) {
                                    if($Domain -ieq "PROG1") {
                                        $SwaggerFiles = "\\$Domain\east\AppsDev\ASPS\Environment\SwaggerServer\$Version"
                                    }
                                    elseif ($Domain -ieq "PROGHSZQ") {
                                        $SwaggerFiles = "\\$Domain\east\AppsHSZQ\ASPS\Environment\SwaggerServer\$Version"
                                    }
                                    else {
                                        # other domains don't have an error so we're going to have fail this part of the action
                                        $SwaggerFiles = "INVALIDDRIVE"
                                    }
                                }
                                $swaggerFiles = $swaggerFiles.TrimEnd("\")

                                # Validate $swaggerFiles has the correct files hosted
                                if((Test-Path "$swaggerFiles\index.html" -PathType Leaf) -and (Test-Path "$swaggerFiles\api-docs" -PathType Container)) {
                                    # determine destination folder
                                    $destination = "d:\inetpub\vserver\$Site\$appFolder"
                                    $sourceFiles = Get-ChildItem "$SwaggerFiles\*.*" -Recurse
                                    Log "Copying $($sourceFiles.Length) file(s) from $SwaggerFiles\*.* to $destination, overwriting only if newer"

                                    foreach($sourceFile in $sourceFiles) {
                                        # calculate the dest file name and create dest folder if needed
                                        $destinationFileName = [string]::Concat($destination.TrimEnd("\"), $sourceFile.FullName.Substring($SwaggerFiles.Length))
                                        $destinationFolder = $destinationFileName.SubString(0, $destinationFileName.LastIndexOf('\'))
                                        if (-not (Test-Path "$destinationFolder" -PathType Container)) {
                                            New-Item -Path "$destinationFolder" -ItemType Directory | Out-Null
                                        }

                                        $destinationFileExists = (Test-Path "$destinationFileName" -PathType Leaf)
                                        # if it doesn't exist, just copy it
                                        if(-not $destinationFileExists) {
                                            Copy-Item -Path "$($sourceFile.FullName)" -Destination "$destinationFileName" -Force
                                            Set-ItemProperty "$destinationFileName" -Name IsReadOnly -Value $false
                                        }
                                        # otherwise copy it if it's newer
                                        elseif($sourceFile.LastWriteTime -gt (Get-Item $destinationFileName).LastWriteTime) {
                                            Copy-Item -Path "$($sourceFile.FullName)" -Destination "$destinationFileName" -Force
                                            Set-ItemProperty "$destinationFileName" -Name IsReadOnly -Value $false
                                        }
                                    }
                                }
                                else {
                                    LogError "$swaggerFiles does not contain SwaggerServer installation files (all other SwaggerServer setup complete otherwise)"
                                    $actionSuccess = $False
                                }

                                # stamp hostHeader into index.html if it's there
                                if((Test-Path "d:\inetpub\vserver\$Site\$appFolder\index.html" -PathType Leaf) -and ($hostHeader -ne $null)) {
                                    # read each line of content and regex replace http://.*/SwaggerServer with the http://$hostheader/SwaggerServer
                                    $htmlContent = Get-Content "d:\inetpub\vserver\$Site\$appFolder\index.html" | % { $_ -Replace "http://.*/SwaggerServer","http://$hostHeader/SwaggerServer"}
                                    $htmlContent | Set-Content "d:\inetpub\vserver\$Site\$appFolder\index.html"
                                }

                                Log ("SUCCESS: Added SwaggerServer v$version as site $site app $appName")
                            }
                            Catch {
                                LogError "Unable to add SwaggerServer v$version as site $site app $appName"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    } 

                    "Model3API.AddSwaggerServer20" {
                        ValidateParamNames $action @("Site","HostHeader","Environment","Port","WebAppManual","DisableGetWebApplications")
                        $site = GetActionParam $action "Site" $True                       
                        $hostHeader = GetActionParam $action "HostHeader" $True
                        $environment = GetActionParam $action "Environment" $False "" @("[ENUM]", "", "Development", "Test", "QA / Acceptance", "Stress", "Production")
                        $port = GetActionParam $action "Port" $False 80
                        $webAppsManual = GetActionParams $action "WebAppManual" $False $null
                        $disableGetWebApplications = GetActionParam $action "DisableGetWebApplications" $False "False" @("[ENUM]", "True", "False")
                        if(Test-Path "D:\Temp\ASPS.AutomateBuild.ToCopy\SwaggerServer20") {
                            $swaggerFiles = "D:\Temp\ASPS.AutomateBuild.ToCopy\SwaggerServer20\2.0"
                        }
                        else {
                            $swaggerFiles = "\\Prog1\east\AppsDev\ASPS\Environment\SwaggerServer\2.0"
                        }
                        Log "  SwaggerFiles=$swaggerFiles"                    
                        Log "  Site=$site"
                        Log "  HostHeader=$hostHeader"
                        Log "  Environment=$environment"
                        Log "  Port=$port"
                        foreach($webAppManual in $webAppsManual) {Log "    WebAppManual=$webAppManual" }
                        Log "  DisableGetWebApplications=$disableGetWebApplications"

                        $appFolder = "SwaggerServer20"
                        $appName = $appFolder
                        $swaggerServerAppPool = "SwaggerServer-$site"



                        if(-not (PSCmdletAvailable "New-WebApplication")) {
                            LogError "Unable to attempt action; New-WebApplication cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {                               
                                Log "Configuring swagger server"
                                
                                #Add Mime Type to ApplicationHost.config
                                LogVerbose "Adding MIME type"
                                if( !((Get-WebConfiguration //staticcontent).collection | ? {$_.fileextension -eq '.json'}) ) {
                                    #Add .json MIME type is not already present
                                    Add-WebConfigurationProperty //staticContent -name collection -value @{fileExtension='.json'; mimeType='application/json'} | Out-Null
                                }

                                #Create Application Pool for Swagger UI (If needed)
                                LogVerbose "Creating app pool $swaggerServerAppPool"
                                if(-not (Test-Path "IIS:\AppPools\$swaggerServerAppPool")) {
                                    New-WebAppPool -Name "$swaggerServerAppPool" | Out-Null
                                }
                                #Updates to ApplicationPool to match current standards
                                if((Get-Item (Join-Path "IIS:\AppPools\" "$swaggerServerAppPool") | select -ExpandProperty managedruntimeversion) -ne 'v4.0') {	
                                    #Updates .Net Framework Version to 4.0
                                    Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name ManagedRuntimeVersion -Value "v4.0"
                                }
                                if((Get-Item (Join-Path "IIS:\AppPools\" "$swaggerServerAppPool") | select -ExpandProperty ManagedPipelineMode) -ne 'Integrated') {
                                    #Updates Managed Pipeline to Integrated
                                    Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name ManagedPipelineMode -Value 0
                                }
                                if((Get-Item (Join-Path "IIS:\AppPools\" "$swaggerServerAppPool") | select -ExpandProperty AutoStart) -ne 'True') {
                                    #Updates AutoStart Propery to True
                                    Set-ItemProperty -Path "IIS:\AppPools\$swaggerServerAppPool" -Name AutoStart -Value $True
                                }

                                #Set AppPool to AppPoolIdentity, add to L-Z-Applications
                                LogVerbose "Setting Identity of $swaggerServerAppPool to ApplicationPoolIdentity"
                                if((Get-Item (Join-Path "IIS:\AppPools\" "$swaggerServerAppPool") | select -ExpandProperty processModel | select -expand identityType) -ne 'ApplicationPoolIdentity') {
                                    #Setting ID to ApplicationPoolIdentity ("4" is ApplicationPoolIdentity)
                                    Set-ItemProperty IIS:\AppPools\$swaggerServerAppPool -name processModel.identityType -value 4
                                }
                                LogVerbose "Add $swaggerServerAppPool to L-Z-Applications"
                                $name = "IIS AppPool\$swaggerServerAppPool"
                                $group = "L-Z-APPLICATIONS"
                                $members = @(net localgroup $group)
                                if($members -inotcontains $name) {
                                    $winNTcomputer = [ADSI]("WinNT://$ComputerName")
                                    $localGroup = $winNTcomputer.psbase.children.find($group)
                                    $localGroup.Add([string]::Concat("WinNT://", $name.Replace("\","/")))
                                }

                                #Create SwaggerServer20 WebApplication
                                LogVerbose "Creating SwaggerServer20 application"
                                if (-not (Test-Path "d:\inetpub\vserver\$site\$appFolder" -PathType Container)) {
                                    New-Item -Path "d:\inetpub\vserver\$site\$appFolder" -ItemType Directory | Out-Null
                                }

                                if((Get-WebApplication -Site "$site" -Name "$appName") -eq $null) {
                                    New-WebApplication -Site "$site" -Name "$appName" -PhysicalPath "d:\inetpub\vserver\$site\$appFolder" -ApplicationPool "$swaggerServerAppPool" | Out-Null
                                }
                                else {
                                    # force the application pool & physical folder
                                    Set-ItemProperty "IIS:\Sites\$site\$appName" -Name ApplicationPool "$swaggerServerAppPool"
                                    Set-ItemProperty "IIS:\Sites\$site\$appName" -Name physicalPath -Value "d:\inetpub\vserver\$Site\$appFolder"
                                }

                                # Set $anonymousAuth, $windowsAuth, $formsAuth
                                LogVerbose "Setting authentication parameters"
                                Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$site/$appName" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value "true"
                                Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$site/$appName" -Filter /system.webServer/security/authentication/anonymousauthentication -Name userName -Value ""
                                Set-WebConfigurationProperty -PSPath "IIS:\" -Location "$site/$appName" -Filter /system.webServer/security/authentication/windowsauthentication -Name enabled -Value "false"

                                #Create SwaggerServer folder and contents
                                $swaggerFiles = $swaggerFiles.TrimEnd("\")

                                # Validate $swaggerFiles has the correct files
                                LogVerbose "Verifying integrity of the source swagger files"
                                if((Test-Path "$swaggerFiles\SwaggerServer\swagger-ui.js" -PathType Leaf) -and (Test-Path "$swaggerFiles\SwaggerServer\o2c.html" -PathType Leaf)) {
                                    # determine destination folder
                                    $destination = "d:\inetpub\vserver\$Site\$appFolder"
                                    $sourceFiles = Get-ChildItem "$SwaggerFiles\SwaggerServer\*.*" -Recurse

                                    foreach($sourceFile in $sourceFiles) {
                                        # calculate the dest file name and create dest folder if needed
                                        $destinationFileName = [string]::Concat($destination.TrimEnd("\"), $sourceFile.FullName.Substring($SwaggerFiles.Length))
                                        $destinationFolder = $destinationFileName.SubString(0, $destinationFileName.LastIndexOf('\'))
                                        if (-not (Test-Path "$destinationFolder" -PathType Container)) {
                                            New-Item -Path "$destinationFolder" -ItemType Directory | Out-Null
                                        }
                                        $destinationFileExists = (Test-Path "$destinationFileName" -PathType Leaf)
                                        # if it doesn't exist, just copy it
                                        if(-not $destinationFileExists) {
                                            Copy-Item -Path "$($sourceFile.FullName)" -Destination "$destinationFileName" -Force
                                            Set-ItemProperty "$destinationFileName" -Name IsReadOnly -Value $false
                                        }
                                        # otherwise copy it if it's newer
                                        elseif($sourceFile.LastWriteTime -gt (Get-Item $destinationFileName).LastWriteTime) {
                                            Copy-Item -Path "$($sourceFile.FullName)" -Destination "$destinationFileName" -Force
                                            Set-ItemProperty "$destinationFileName" -Name IsReadOnly -Value $false
                                        }
                                    }
                                }

                                # Create SwaggerServer as sub app under $Site/SwaggerServer
                                LogVerbose "Creating SwaggerServer app under $site/SwaggerServer"
                                if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\SwaggerServer" -PathType Container)) {
                                    New-Item -Path "d:\inetpub\vserver\$Site\$appFolder\SwaggerServer" -ItemType Directory | Out-Null
                                }
                                if((Get-WebApplication -Site "$Site" -Name "$appName/SwaggerServer") -eq $null) {
                                    New-WebApplication -Site "$Site" -Name "$appName/SwaggerServer" -PhysicalPath "d:\inetpub\vserver\$Site\$appFolder\SwaggerServer" -ApplicationPool "$swaggerServerAppPool" | Out-Null
                                }
                                else {
                                    # force the application pool & physical folder
                                    Set-ItemProperty "IIS:\Sites\$site\$appName\SwaggerServer" -Name ApplicationPool "$swaggerServerAppPool"
                                    Set-ItemProperty "IIS:\Sites\$site\$appName\SwaggerServer" -Name physicalPath -Value "d:\inetpub\vserver\$Site\$appFolder\SwaggerServer"
                                }

                                # Create subfolders based on Virtual Applications under the site hosting SwaggerServer
                                LogVerbose "Creating a subfolder per API under SwaggerServer site"                         
                                if ($disableGetWebApplications -eq "False") {
                                    #Gather existing virtual applications from IIS
                                    $webApps = (Get-Webapplication -Site "$Site" | select @{e={$_.Path.Trim('/')};l="Name"} | where-object Name -NotLike '*Swagger*' | sort Name -Descending | Foreach {"$($_.Name)"})
                                }
                                #Sort manual virtual applications for Swagger
                                $webAppsManual = $webAppsManual | sort -Descending
                                $array = @()
                                #IIS WebApps add to array
                                foreach ($app in $webApps) {
                                    $addLine = new-object psobject
                                    $addLine | Add-Member -MemberType NoteProperty -Name "Name" -Value $app
                                    $array += $addLine
                                }
                                #Manual WebApps add to array
                                foreach ($app in $webAppsManual) {
                                    $addLine = new-object psobject
                                    $addLine | Add-Member -membertype NoteProperty -Name "Name" -Value $app
                                    $array += $addLine
                                }
                                
                                $array |
                                    % {
                                        $webAppName = ($_.Name.Split('/')[0])
                                        $webAppName1 = ($_.Name.Split('/')[1])
                                        if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName" -PathType Container)) {
                                            New-Item -Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName" -ItemType Directory | Out-Null
                                        }
                                        if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs" -PathType Container)) {
                                            New-Item -Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs" -ItemType Directory | Out-Null
                                        }
                                        if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\$webAppName1" -PathType Container)) {
                                            New-Item -Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\$webAppName1" -ItemType Directory | Out-Null
                                        }
                                        if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\index.html" -PathType Leaf)) {
                                            Copy-Item "$swaggerFiles\Files2Convert\index.html" "d:\inetpub\vserver\$Site\$appFolder\$webAppName"
                                        }
                                        if(Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\index.html" -PathType Leaf)  {
                                            # read each line of content and regex replace http://.*/SwaggerServer with the http://$hostheader/SwaggerServer
                                            $htmlContent = Get-Content "d:\inetpub\vserver\$Site\$appFolder\$webAppName\index.html" | 
                                                % { $_ -Replace "REPLACE_HOSTHEADER","$hostHeader"} | 
                                                % { $_ -Replace "REPLACE_APINAME","$webAppName"} | 
                                                % { $_ -Replace "REPLACE_ENVIRONMENT","$environment"} | 
                                                % { $_ -Replace "REPLACE_PORT","$port"} | 
                                                Where-Object {!(Get-Content "d:\inetpub\vserver\$Site\$appFolder\$webAppName\index.html" | Select-String -SimpleMatch "api-docs/$webAppName1/$webAppName.json")} |
                                                % {$_ 
                                                    if ($_ -match "<!-- TODO: Add Additional options for each slot, use Parent as an example -->") { 
                                                        $slotString = "<option value=api-docs/$webAppName1/$webAppName.json>$webAppName1</option>"
                                                        if($slotString -ne "<option value=api-docs//$webAppName.json></option>") {
                                                            "`t`t`t`t`t`t`t`t`t`t`t$slotString"
                                                        }
                                                    } 
                                                }
                                            $htmlContent | Set-Content "d:\inetpub\vserver\$Site\$appFolder\$webAppName\index.html"
                                        }
        
                                        if (-not (Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\parent.json" -PathType Leaf)) {
                                            Copy-Item "$SwaggerFiles\Files2Convert\parent.json" "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs"
                                            if(Test-Path "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\parent.json" -PathType Leaf) {
                                                # read each line of content and regex replace http://.*/SwaggerServer with the http://$hostheader/SwaggerServer
                                                $htmlContent = Get-Content "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\parent.json" | 
                                                    % { $_ -Replace "REPLACE_HOSTHEADER","$hostHeader"} | 
                                                    % { $_ -Replace "REPLACE_APINAME","$webAppName"} | 
                                                    % { $_ -Replace "REPLACE_ENVIRONMENT","$environment"} | 
                                                    % { $_ -Replace "REPLACE_PORT","$port"}
                                                $htmlContent | Set-Content "d:\inetpub\vserver\$Site\$appFolder\$webAppName\api-docs\parent.json"
                                            }
                                        }      
                                    } 
                            }
                            Catch {
                                LogError "Unable to add SwaggerServer as site $site app $appName"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }
                    
                    "Model3API.AddAPI" {
                        ValidateParamNames $action @("Site","API", "Slot", "PoolUserName","AnonymousAuth","PoolFramework","AnonymousAuthUserName","WindowsAuth", "ShareAppPool")
                        $site = GetActionParam $action "Site" $True
                        $apis = GetActionParams $action "API" $True
                        $slots = GetActionParams $action "Slot" $False $null
                        $poolUserName = GetActionParam $action "PoolUserName" $True $null @("[REGEX]", "^[A-Za-z0-9]+\\[A-Za-z0-9]+$")
                        $poolFramework = GetActionParam $action "PoolFramework" $False "v4.0" @("[ENUM]", "v2.0", "v4.0")
                        $anonymousAuth = GetActionParam $action "AnonymousAuth" $False $null @("[BOOL]")
                        $anonymousAuthUserName = GetActionParam $action "AnonymousAuthUserName" $False $null
                        $windowsAuth = GetActionParam $action "WindowsAuth" $False $null @("[BOOL]")
                        $shareAppPool = GetActionParam $action "ShareAppPool" $False $False @("[BOOL]")
                        $shareAppPool = (($shareAppPool -ieq "true") -or ($shareAppPool -eq $True))
                        Log "  Site=$site"
                        foreach($api in $apis) { Log "  API=$api" }
                        foreach($slot in $slots) { Log "  Slot=$slot" }
                        Log "  PoolUserName=$poolUserName"
                        Log "  PoolFramework=$poolFramework"
                        Log "  AnonymousAuth=$anonymousAuth"
                        Log "  AnonymousAuthUserName=$anonymousAuthUserName"
                        Log "  WindowsAuth=$windowsAuth"
                        Log "  ShareAppPool=$shareAppPool"

                        # build list of referenced service accounts
                        if(-not ($serviceAccountList -icontains $poolUserName)) {
                            $serviceAccountList += [array]$poolUserName
                        }

                        if(-not (PSCmdletAvailable "New-WebApplication")) {
                            LogError "Unable to attempt action; New-WebApplication cmdlet not available"
                            $actionSuccess = $whatIf.IsPresent
                        }
                        elseif(-not $whatIf.IsPresent) {
                            Try {
                                foreach($api in $apis) {
                                    Log "Configuring API $api"
                                    Log "  Creating Progressive Applications event source $api"
                                    New-EventLog -LogName "Progressive Applications" -Source "$api" -ErrorAction Ignore

                                    # Create app pool $API using $ZID
                                    Log "  Creating application pool $api"
                                    if(-not (Test-Path "IIS:\AppPools\$api")) {
                                        New-WebAppPool -Name "$api" | Out-Null
                                    }
                                    Set-ItemProperty -Path "IIS:\AppPools\$api" -Name ManagedRuntimeVersion -Value "$poolFramework"
                                    Set-ItemProperty -Path "IIS:\AppPools\$api" -Name ManagedPipelineMode -Value 0
                                    Set-ItemProperty -Path "IIS:\AppPools\$api" -Name autoStart -Value $True

                                    # Create site $site app /$api using d:\inetpub\vserver\$Site\$api and app pool $api
                                    $pool = Get-Item "IIS:\AppPools\$api"
                                    $pool.processModel.identityType = 3
                                    $pool.processModel.userName = "$poolUserName"
                                    $pool.processModel.password = "$(GetPassword $cachedPasswords $poolUserName)"
                                    $pool | Set-Item

                                    Log "  Creating physical folder d:\inetpub\vserver\$site\$api"
                                    if (-not (Test-Path "d:\inetpub\vserver\$site\$api" -PathType Container)) {
                                        New-Item -Path "d:\inetpub\vserver\$site\$api" -ItemType Directory | Out-Null
                                    }

                                    Log "  Creating site $site app $api using d:\inetpub\vserver\$site\$api and app pool $api"
                                    if((Get-WebApplication -Site "$site" -Name "$api") -eq $null) {
                                        New-WebApplication -Site "$site" -Name "$api" -PhysicalPath "d:\inetpub\vserver\$site\$api" -ApplicationPool "$api" | Out-Null
                                    }
                                    else {
                                        Set-ItemProperty "IIS:\Sites\$site\$api" -Name ApplicationPool "$api"
                                        Set-ItemProperty "IIS:\Sites\$site\$api" -Name physicalPath -Value "d:\inetpub\vserver\$site\$api"
                                    }

                                    # Set anonymousAuth to use app pool identity
                                    Log "  Setting site $site app $api authentication settings"
                                    if($anonymousAuth -eq "") {
                                        Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled
                                    }
                                    elseif($anonymousAuth -ne $null) {
                                        Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value "$anonymousAuth"
                                    }
                                    if($anonymousAuthUserName -ne $null) {
                                        Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api" -Filter system.webServer/security/authentication/anonymousauthentication -Name userName -Value "$anonymousAuthUserName"
                                    }
                                    if($windowsAuth -eq "") {
                                        Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                    }
                                    elseif($windowsAuth -ne $null) {
                                        Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value "$windowsAuth"
                                    }

                                    Log "  SUCCESS: Added API $api under site $site"

                                    foreach($slot in $slots) {
                                        Log "  Configuring API $api slot $slot"
                                        # Create app pool $API using $ZID
                                        if($shareAppPool) {
                                            $appPoolName = "$api"
                                            Log "    Sharing application pool $appPoolName"
                                        }
                                        else {
                                            $appPoolName = "$api-$slot"
                                            Log "    Creating application pool $appPoolName"
                                            if(-not (Test-Path "IIS:\AppPools\$appPoolName")) {
                                                New-WebAppPool -Name "$appPoolName" | Out-Null
                                            }
                                            Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name ManagedRuntimeVersion -Value "$poolFramework"
                                            Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name ManagedPipelineMode -Value 0
                                            Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name autoStart -Value $True

                                            # Create site $site app /$api/$slot using d:\inetpub\vserver\$Site\$api\$slot and app pool $api
                                            $pool = Get-Item "IIS:\AppPools\$appPoolName"
                                            $pool.processModel.identityType = 3
                                            $pool.processModel.userName = "$poolUserName"
                                            $pool.processModel.password = "$(GetPassword $cachedPasswords $poolUserName)"
                                            $pool | Set-Item
                                        }

                                        Log "    Creating physical folder d:\inetpub\vserver\$site\$api\$slot"
                                        if (-not (Test-Path "d:\inetpub\vserver\$site\$api\$slot" -PathType Container)) {
                                            New-Item -Path "d:\inetpub\vserver\$site\$api\$slot" -ItemType Directory | Out-Null
                                        }

                                        Log "    Creating site $site app $api/$slot using d:\inetpub\vserver\$site\$api\$slot and app pool $appPoolName"
                                        if((Get-WebApplication -Site "$site" -Name "$api/$slot") -eq $null) {
                                            New-WebApplication -Site "$site" -Name "$api/$slot" -PhysicalPath "d:\inetpub\vserver\$site\$api\$slot" -ApplicationPool "$appPoolName" | Out-Null
                                        }
                                        else {
                                            Set-ItemProperty "IIS:\Sites\$site\$api\$slot" -Name ApplicationPool "$appPoolName"
                                            Set-ItemProperty "IIS:\Sites\$site\$api\$slot" -Name physicalPath -Value "d:\inetpub\vserver\$site\$api\$slot"
                                        }

                                        # Set anonymousAuth to use app pool identity
                                        Log "    Setting site $site app $api/$slot authentication settings"
                                        if($anonymousAuth -eq "") {
                                            Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api/$slot" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled
                                        }
                                        elseif($anonymousAuth -ne $null) {
                                            Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api/$slot" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name Enabled -Value "$anonymousAuth"
                                        }
                                        if($anonymousAuthUserName -ne $null) {
                                            Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api/$slot" -Filter system.webServer/security/authentication/anonymousauthentication -Name userName -Value "$anonymousAuthUserName"
                                        }
                                        if($windowsAuth -eq "") {
                                            Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api/$slot" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled
                                        }
                                        elseif($windowsAuth -ne $null) {
                                            Set-WebConfigurationProperty -PSPath "IIS:\Sites\$site" -Location "$api/$slot" -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -Value "$windowsAuth"
                                        }

                                        Log "    SUCCESS: Added API $api slot $slot under site $site"
                                    }
                                }

                                # add to SwaggerServer 1.2?
                                $swaggerFolder = "D:\inetpub\vserver\$site\SwaggerServer"
                                if(Test-Path "$swaggerFolder" -PathType Container) {
                                    Log "Adding APIs and slots to SwaggerServer 1.2"
                                    # find existing API.json files in case you need one
                                    $apiJSONs = (get-childitem "D:\inetpub\vserver\$site\SwaggerServer\api-docs\$api.json" -Recurse)
                                    if($apiJSONs -ne $null) {
                                        $sampleJSON = $apiJSONs[0].FullName
                                        $sampleWebConfig = [string]::Concat($apiJSONs[0].Directory.FullName, '\web.config')
                                    }
                                    else {
                                        $apiJSONs = (get-childitem "D:\inetpub\vserver\$site\SwaggerServer\api-docs\SampleApp.json" -Recurse)
                                        if($apiJSONs -ne $null) {
                                            $sampleJSON = $apiJSONs[0].FullName
                                            $sampleWebConfig = [string]::Concat($apiJSONs[0].Directory.FullName, '\web.config')
                                        }
                                        else {
                                            $sampleJSON = $null
                                        }
                                    }

                                    foreach($api in $apis) {
                                        Log "Adding API $api"
                                        # create $swaggerFolder\api-docs\$api\$api.json if needed
                                        Log "  Creating physical folder $swaggerFolder\api-docs\$api with $api.json and web.config"
                                        if (-not (Test-Path "$swaggerFolder\api-docs\$api" -PathType Container)) {
                                            New-Item -Path "$swaggerFolder\api-docs\$api" -ItemType Directory | Out-Null
                                        }
                                        if($sampleJSON -ne $null) {
                                            Log "  Copying example $api.json and web.config (if not already present)"
                                            if (-not (Test-Path "$swaggerFolder\api-docs\$api\$api.json" -PathType Leaf)) {
                                                Copy-Item -Path "$sampleJSON" -Destination "$swaggerFolder\api-docs\$api\$api.json"
                                                Set-ItemProperty "$swaggerFolder\api-docs\$api\$api.json" -Name IsReadOnly -Value $false
                                            }
                                            if (-not (Test-Path "$swaggerFolder\api-docs\$api\web.config" -PathType Leaf)) {
                                                Copy-Item -Path "$sampleWebConfig" -Destination "$swaggerFolder\api-docs\$api\web.config"
                                                Set-ItemProperty "$swaggerFolder\api-docs\$api\web.config" -Name IsReadOnly -Value $false
                                            }
		
                                            # Alter $swaggerFolder\api-docs\$api\web.config to point to $api.json
                                            Set-ItemProperty "$swaggerFolder\api-docs\$api\web.config" -Name IsReadOnly -Value $false
                                            [xml]$webConfigXML = Get-Content "$swaggerFolder\api-docs\$api\web.config"
                                            $valueAttr = $webConfigXML.SelectSingleNode("//files/add/@value")
                                            $valueAttr.Value = "$api.json"
                                            $webConfigXML.Save("$swaggerFolder\api-docs\$api\web.config")
                                        }
                                        else {
                                            Log "  Unable to copy example $api.json and web.config"
                                        }
                                        Log "  SUCCESS: Added api $api - you may still need to manually edit $swaggerFolder\api-docs\api-docs.json"

                                        # add each slot
                                        foreach($slot in $slots) {
                                            Log "  Adding API $api slot $slot"
                                            # create $swaggerFolder\api-docs\$api-$slot\$api.json if needed
                                            Log "    Creating physical folder $swaggerFolder\api-docs\$api-$slot with $api.json and web.config"
                                            if (-not (Test-Path "$swaggerFolder\api-docs\$api-$slot" -PathType Container)) {
                                                New-Item -Path "$swaggerFolder\api-docs\$api-$slot" -ItemType Directory | Out-Null
                                            }
                                            # copy example files if you found them
                                            if($sampleJSON -ne $null) {
                                                Log "    Copying example $api.json and web.config (if not already present)"
                                                if (-not (Test-Path "$swaggerFolder\api-docs\$api-$slot\$api.json" -PathType Leaf)) {
                                                    Copy-Item -Path "$sampleJSON" -Destination "$swaggerFolder\api-docs\$api-$slot\$api.json"
                                                    Set-ItemProperty "$swaggerFolder\api-docs\$api-$slot\$api.json" -Name IsReadOnly -Value $false
                                                }
                                                if (-not (Test-Path "$swaggerFolder\api-docs\$api-$slot\web.config" -PathType Leaf)) {
                                                    Copy-Item -Path "$sampleWebConfig" -Destination "$swaggerFolder\api-docs\$api-$slot\web.config"
                                                    Set-ItemProperty "$swaggerFolder\api-docs\$api-$slot\web.config" -Name IsReadOnly -Value $false
                                                }
		
                                                # Alter $swaggerFolder\api-docs\$api-$slot\web.config to point to $api.json
                                                Set-ItemProperty "$swaggerFolder\api-docs\$api-$slot\web.config" -Name IsReadOnly -Value $false
                                                [xml]$webConfigXML = Get-Content "$swaggerFolder\api-docs\$api-$slot\web.config"
                                                $valueAttr = $webConfigXML.SelectSingleNode("//files/add/@value")
                                                $valueAttr.Value = "$api.json"
                                                $webConfigXML.Save("$swaggerFolder\api-docs\$api-$slot\web.config")
                                            }
                                            else {
                                                Log "    Unable to copy example $api.json and web.config"
                                            }
                                            Log "    SUCCESS: Added api $api slot $slot - you may still need to manually edit $swaggerFolder\api-docs\api-docs.json"
                                        }
                                    }
                                }

                                # add to SwaggerServer 2.0?
                                $swaggerFolder = "D:\inetpub\vserver\$site\SwaggerServer20"
                                if(Test-Path "$swaggerFolder" -PathType Container) {
                                    Log "Adding APIs and slots to SwaggerServer 2.0"
                                    foreach($api in $apis) {
                                        Log "Adding API $api"
                                        # create $swaggerFolder\api-docs\$api\$api.json if needed
                                        Log "  Creating physical folder $swaggerFolder\api-docs\$api"
                                        if (-not (Test-Path "$swaggerFolder\api-docs\$api" -PathType Container)) {
                                            New-Item -Path "$swaggerFolder\api-docs\$api" -ItemType Directory | Out-Null
                                        }
		                                Log "  SUCCESS: Added api $api - you may still need to manually edit $swaggerFolder\api-docs\parent.json"

                                        # add each slot
                                        foreach($slot in $slots) {
                                            Log "  Adding API $api slot $slot"
                                            # create $swaggerFolder\api-docs\$api-$slot\$api.json if needed
                                            Log "    Creating physical folder $swaggerFolder\api-docs\$api\$slot"
                                            if (-not (Test-Path "$swaggerFolder\api-docs\$api\$slot" -PathType Container)) {
                                                New-Item -Path "$swaggerFolder\api-docs\$api\$slot" -ItemType Directory | Out-Null
                                            }						
                                            Log "    SUCCESS: Added api $api slot $slot - you may still need to manually edit $swaggerFolder\api-docs\parent.json"
                                        }
                                    }
                                }
                            }
                            Catch {
                                LogError "Unable to add API(s) and slot(s) to site $site"
                                Log ("  Exception Type: $($_.Exception.GetType().FullName)")
                                Log ("  Exception Message: $($_.Exception.Message)")
                                $actionSuccess = $False
                            }
                        }
                    }

                    default {
                        $error = "Unknown Action type $actionType"
                        LogError $error
                        $actionSuccess = $False
                    }
                }

                # if action failed, the action might have special handling for an error
                if(-not $actionSuccess) {
                    # did the script writer
                    if($actionErrorTip -ne $null) {
                        Log "*** NOTE: The script provides the following tip if the action failed: $actionErrorTip"
                    }
                    # did the action request to ignore the error (i.e. treat as "success")
                    if($actionOnError -ieq "Ignore") {
                        $actionSuccess = $true
                        $countIgnoredError += 1
                    }
                    elseif($actionOnError -ieq "Abort") {
                        AbortWithError EXIT_ACTION_FAILED "$actionType Action failed and was set to abort the script on failure"
                    }
                    elseif($actionOnError -ieq "Pause") {
                        # pause for user input first
                        if(-not $Quiet) {
                            $note = Read-Host "Action specifies to pause for input on error"
                        }
                    }
                    # fall through to global setting to abort on error
                    elseif($OnError -ieq "Abort") {
                        AbortWithError EXIT_ACTION_FAILED "$actionType Action failed and user specified to abort the script on any failure"
                    }
                    elseif($OnError -ieq "Pause") {
                        if(-not $Quiet) {
                            $note = Read-Host "User specified to pause for input on error"
                        }
                    }
                }

                if($actionID -ne "") { $actionResults[$actionID] = $actionSuccess }

                if($actionSuccess) { $countSucceeded += 1 }
                else { $countFailed += 1 }
            }
    #endregion
        }
    }

    # log out summary results
    Log "============================================================"
    Log "Completed!"
    Log ""
    Log "Selected Actions = $($actions.Count)"
    Log "  Attempted = $countAttempts"
    Log "  - Succeeded = $countSucceeded (including $countIgnoredError ignored error(s))"
    Log "  - Failed = $countFailed (TIP: Search above for ""ERROR"")"
    Log "  Skipped = $countSkips (TIP: Search above for ""skipping"")"
    Log "  Conditions not met = $countNotApplicable"
    Log ""
    Log "Service accounts referenced:"
    $serviceAccountList | % { Log "  $_" }
    # look for errors from not running as Admin
    if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -and ($countFailed -gt 0)) {
        Log ""
        Log "NOTE: One of more of your errors may be coming from not running this script as an Administrator"
    }
    Log ""
    Log "See also $logFile"
    if($reminderList.Length -gt 0) {
        Log ""
        Log "Reminders set by the instructions:"
        $reminderList | % { "[  ] $_" }
    }

    if(-not $whatIf.IsPresent) {
        New-ItemProperty -Path $KEY_LOCATION -Name "FinishTime" -Value $(Get-Date -format "yyyy-MM-dd HH:mm:ss") -Force -ErrorAction Ignore | Out-Null
    }
}