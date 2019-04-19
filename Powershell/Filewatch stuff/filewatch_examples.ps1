#watching for file changes stuff
Function Register-Watcher {
    param ($folder)
    $filter = "*.*" #all files
    $watcher = New-Object IO.FileSystemWatcher $folder, $filter -Property @{ 
        IncludeSubdirectories = $false
        EnableRaisingEvents = $true
    }

    $changeAction = [scriptblock]::Create('
        # This is the code which will be executed every time a file change is detected
        $path = $Event.SourceEventArgs.FullPath
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $timeStamp = $Event.TimeGenerated
        Write-Host "The file $name was $changeType at $timeStamp"
    ')

    Register-ObjectEvent $Watcher "Changed" -Action $changeAction
}

 Register-Watcher "c:\temp"

####alternative


 $File = "C:\temp\log.txt"
$Action = 'Write-Output "The watched file was changed"'
$global:FileChanged = $false

function Wait-FileChange {
    param(
        [string]$File,
        [string]$Action
    )
    $FilePath = Split-Path $File -Parent
    $FileName = Split-Path $File -Leaf
    $ScriptBlock = [scriptblock]::Create($Action)

    $Watcher = New-Object IO.FileSystemWatcher $FilePath, $FileName -Property @{ 
        IncludeSubdirectories = $false
        EnableRaisingEvents = $true
    }
    $onChange = Register-ObjectEvent $Watcher Changed -Action {$global:FileChanged = $true}

    while ($global:FileChanged -eq $false){
        Start-Sleep -Milliseconds 100
    }

    & $ScriptBlock 
    Unregister-Event -SubscriptionId $onChange.Id
}

Wait-FileChange -File $File -Action $Action




#to unregister, or stop the watcher
Unregister-Event $created.Id