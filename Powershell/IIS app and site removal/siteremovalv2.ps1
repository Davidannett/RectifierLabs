import-module WebAdministration
Stop-WebAppPool -Name ComparativeRater
Remove-WebAppPool ComparativeRater
remove-website -name ComparativeRater
//Remove-Item -Path 'D:\inetpub\vserver\Raters' -Recurse -Force -Confirm:$false