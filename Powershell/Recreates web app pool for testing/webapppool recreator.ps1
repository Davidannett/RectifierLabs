$Site = 'Progressive Default Site'
$WebAppNames = "Css.Mapping.CSCService", "Css.Mapping.CSCServiceTestPages"

     
foreach($App in $WebAppNames){
 new-webapppool -name $app
 Start-WebAppPool -Name $App
 new-item -itemtype directory -Path "d:\inetpub\vserver\$app"
 New-WebApplication -site $Site -Name $App -PhysicalPath "d:\inetpub\vserver\$app" -ApplicationPool $App  
}