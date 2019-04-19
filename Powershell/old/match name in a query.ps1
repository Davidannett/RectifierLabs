#working script


Get-WebApplication -name Css.Mapping.CSCService* | select @{e={$_.Path.Trim('/')};l="Name"}