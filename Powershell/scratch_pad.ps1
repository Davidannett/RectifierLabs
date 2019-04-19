#password encryption stuff
$response = Read-host "Enter ZID password" -AsSecureString 
$password=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($response))


#see how long a process has been running (process name could be a service executable so it applies to services as well)
New-TimeSpan -Start (get-process process_name).StartTime
New-TimeSpan -Start (get-process ContentSharingUploadService).StartTime

#function to load webadmin module based on OS version
function LoadAdminModules
{
    if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1"){
        if (Get-Module -ListAvailable -Name WebAdministration){
            Import-Module WebAdministration -force
            write-host "load1"
        }
    } 
        else {
            Add-PSSnapin WebAdministration
            write-host "load2"
        }
}


#check and restart powershell session if not running as administrator


#if statement checks for various things
if($arrService.Status -ne 'Running'){}
if(-not (test-path $TaskPath)){}
if(Get-ScheduledTask | Where-Object {$_.TaskName -like $TaskName1 }){}
If((Get-LocalGroupMember "Administrators").Name -contains $user){}
If(Get-Service LogWatch | Where-Object {$_.Status -match “Running”}){}
if ($Return.ReturnValue -eq 0)
if (!(Test-Path $homedir\$slot\$appname))
if (Test-Path $homedir\$slot)



#splits and using commas for multiple entires
$appnames = (Read-Host "Enter the names of the apps you wish to create(Seperate with comma)").Split(',') | %{$_.trim()}      # the pipe to trim removes all preceeding and trailing whitespace (% means foreach-object)

#add user to local group
Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24D"

#check if user is added to group
If((Get-LocalGroupMember "Administrators").Name -contains $user){
    Write-Host -fore Cyan "$user properly added to local Administrators group"
}

#switch to match names
$localhostname = "$env:COMPUTERNAME"

Switch ($localhostname){
    SCCNSHD1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24D"}
    SCCNSHQ1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24Q"}
    SCCNSHS1 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24k"}
    SCCNSHD2 {Add-LocalGroupMember -Group "Administrators" -member "ProgHSZQ\ZCLMS24k"}
}

#Checks if you are running Powershell as Administrator.  If not, launches a new console as Administrator and runs script from there.
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}"' -f ($myinvocation.MyCommand.Definition))
    exit
    }

#match IIS app by name
Get-WebApplication -name Css.Mapping.CSCService* | select-object @{e={$_.Path.Trim('/')};l="Name"}


#a DO while example
$a = 1 
DO{
 "Starting Loop $a"
 $a
 $a++
 "Now `$a is $a"
}
While ($a -le 5)

#writing to an event log
Write-EventLog -LogName "Application" -Source "MyApp" -EventID 3001 -EntryType Information -Message "MyApp added a user-requested feature to the display." -Category 1 -RawData 10,20

#logging idea
Write-Output "$('[{0:MM/dd/yyyy} {0:HH:mm:ss}]' -f (Get-Date)) I can connect to $dc" | Out-file C:\dclog.txt -append

#progress bars
$TotalSteps = 4
$Step       = 1
$StepText   = "Setting Initial Variables"
$StatusText = '"Step $($Step.ToString().PadLeft($TotalSteps.Count.ToString().Length)) of $TotalSteps | $StepText"'
$StatusBlock = [ScriptBlock]::Create($StatusText)
$Task        = "Creating Progress Bar Script Block for Groups"
Write-Progress -Id $Id -Activity $Activity -Status (&amp; $StatusBlock) -CurrentOperation $Task -PercentComplete ($Step / $TotalSteps * 100)



#temporarily disable website form restarting
Set-ItemProperty "IIS:\Sites\Default Web Site" serverAutoStart False


#check for named software installed
If(Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like 'Pxpoint'"){
    write-host "good"
    }
Else{
    write-host "bad"
}

#general software queries, 3 flavors (none optimized)
Get-WmiObject -Class Win32_Product | Select-Object -Property Name
Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like 'Pxpoint'"
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match “Pxpoint”}

#check if service is running
If(Get-Service LogWatch | Where-Object {$_.Status -match “Running”}){
    write-host "running"
}
Else{
    write-host "not running"
}

#uninstall
$appremove = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match “Pxpoint”}
$appremove.Uninstall()          #return code of 0 is success

    #or
    Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match “Pxpoint”} | forEach-Object { $_.Uninstall()}

#press enter to continue
[void](Read-Host 'Press Enter to continue…')


#validate AD credentials (need to be made domain agnostic)
function credchk
{
 $global:serviceAccount = Read-Host "Enter Z-ID"
 $global:password = Read-host "Enter PASSWORD"

 CLS

 #lookup
   $global:domain = New-Object System.DirectoryServices.DirectoryEntry($global:domainName,$global:serviceAccount,$global:password)
 
 "Validating Credentials"
  sleep -seconds 2

 #popup
   if ($global:domain.name -eq $null)
    {
     $failpop = New-Object -ComObject wscript.shell
     $failpopmsg = $failpop.popup("Authentication failed for $global:acctdomain\$global:serviceAccount with password=$global:password - please verify your username and password and TRY AGAIN. Also verify if the username has machine logon access to this server" ,0, "Authentication Failed!" , 5)
    }

   else
    {
      $successpop = New-Object -ComObject wscript.shell
      $successpopmsg = $successpop.popup("Successfully authenticated $global:acctdomain\$global:serviceAccount at $date" ,5, "Success!" , 0)
      $global:valid = "true"
    }
  
  CLS       
 }

 #loop in a function
 do {credchk} while ($global:valid -ne $true)