function Test-WEbconfigRegistry
    {
    $path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp\Configuration'
    $value = 'MaxWebConfigFileSizeInKB'
    Try
    {
    Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object -ExpandProperty $value -ErrorAction STop | Out-Null
    Set-ItemProperty -Path $path -Name MaxWebConfigFileSizeInKB -Value 500 -ErrorAction Stop
    Write-Host "Key was already there and was updated.  Please verify in regedit"
    Return $true
    }
    Catch
    {
    $createpath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp'
    New-Item -path $createpath -Name Configuration 
    New-ItemProperty -Path $path -Name MaxWebConfigFileSizeInKB -Value 500 -PropertyType DWORD
    Write-Host "key successfully CREATED and Updated Please Verify"
    Return $false
    }
    }
Test-WEbconfigRegistry
IISReset