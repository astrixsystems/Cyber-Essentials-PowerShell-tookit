<#
.SYNOPSIS
	Name: List-EndpointProtection.ps1
	The purpose of this script is to determine what endpoint protection is used.
	
.DESCRIPTION
	The purpose of this script is to gather information on what endpoint protection is used in order to comply with Cyber Essentials Plus.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.List-EndpointProtection.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.NOTES
	Author:				Ben Hooper at Astrix
	Created:			2018/09/06
	Tested on:			Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Updated:			2018/09/11
	Version:			1.2
	Changes in v1.2:	Removed requirement for administrative permissions
	Changes in v1.1:	Added case handling where no endpoint protection apps are found.

.EXAMPLE
	Run with the default settings:
		List-EndpointProtection
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		List-EndpointProtection -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		List-EndpointProtection -LogOutput -LogPath "C:\$env:computername.List-EndpointProtection.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		List-EndpointProtection -LogOutput -LogPath "\\servername\filesharename\$env:computername.List-EndpointProtection.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$LogPath_Default = "C:\$env:computername.List-EndpointProtection.txt";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function List-EndpointProtection {
	Param()
	
	Begin {
		Write-Output "Searching for installed endpoint protection / security applications...";
		Write-Output "";
	}
	
	Process {
		Try {
			$EP_Active = $False;
			
			$EPApps = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct;
			
			If ($EPApps -NE $Null){
				ForEach ($EPApp in $EPApps) {
					$EPApp_Name = $EPApp.displayName;
					Write-Output "`t Found endpoint protection app '$EPApp_Name'. Analysing...";
					Write-Output "`t `t Detecting status...";
					
					$EPApp_Status = $EPApp.productState;
					Switch ($EPApp_Status) {
						"262144" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"262160" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"266240" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						"266256" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						"393216" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"393232" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"393472" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"393488" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Disabled";}
						"397312" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						"397328" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						"397568" {$EPApp_Status_Definitions = "Up-to-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						"397584" {$EPApp_Status_Definitions = "Out-of-date"; $EPApp_Status_RealTimeProtection = "Enabled";}
						Default {$EPApp_Status_Definitions = "Unknown"; $EPApp_Status_RealTimeProtection = "Unknown";}
					}
					
					Write-Output "`t `t `t Definitions: $EPApp_Status_Definitions.";
					Write-Output "`t `t `t Real-time protection: $EPApp_Status_RealTimeProtection.";
					
					If ($EP_Active -Eq $False){
						If (($EPApp_Status_Definitions -Eq "Up-to-date") -And ($EPApp_Status_RealTimeProtection -Eq "Enabled")){
							$EP_Active = $True;
						}
					}
					
					Write-Output "";
				}
				
				If ($EP_Active -Eq $True){
					Write-Output "This computer IS protected by at least one endpoint protection app that is up-to-date AND enabled.";
				} Else {
					Write-Output "This computer IS NOT protected by at least one up-to-date and active endpoint protection app.";
				}
			} ElseIf ($EPApps -Eq $Null) {
				Write-Output "NO endpoint protection apps found!";
			}
		}
		
		Catch {
			Write-Output "";
			Write-Output "`t ...FAILURE. Something went wrong.";
			Break;
		}
	}
	
	End {
		If($?){ # only execute if the function was successful.
			
		}
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($LogOutput -Eq $True) {
	If (-Not $LogPath) {
		$LogPath = $LogPath_Default;
	}
	Start-Transcript -Path $LogPath -Append | Out-Null;
}

List-EndpointProtection;

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIVMAYJKoZIhvcNAQcCoIIVITCCFR0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULPqbFJpzpejKhq1B3Ef8EHBb
# /I2gghAfMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
# BQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQg
# TGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNV
# BAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJG
# aXJzdC1PYmplY3QwHhcNMTUxMjMxMDAwMDAwWhcNMTkwNzA5MTg0MDM2WjCBhDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKjAoBgNVBAMT
# IUNPTU9ETyBTSEEtMSBUaW1lIFN0YW1waW5nIFNpZ25lcjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAOnpPd/XNwjJHjiyUlNCbSLxscQGBGue/YJ0UEN9
# xqC7H075AnEmse9D2IOMSPznD5d6muuc3qajDjscRBh1jnilF2n+SRik4rtcTv6O
# KlR6UPDV9syR55l51955lNeWM/4Og74iv2MWLKPdKBuvPavql9LxvwQQ5z1IRf0f
# aGXBf1mZacAiMQxibqdcZQEhsGPEIhgn7ub80gA9Ry6ouIZWXQTcExclbhzfRA8V
# zbfbpVd2Qm8AaIKZ0uPB3vCLlFdM7AiQIiHOIiuYDELmQpOUmJPv/QbZP7xbm1Q8
# ILHuatZHesWrgOkwmt7xpD9VTQoJNIp1KdJprZcPUL/4ygkCAwEAAaOB9DCB8TAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUjmstM2v0
# M6eTsxOapeAK9xI1aogwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny
# bC51c2VydHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDA1BggrBgEF
# BQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20w
# DQYJKoZIhvcNAQEFBQADggEBALozJEBAjHzbWJ+zYJiy9cAx/usfblD2CuDk5oGt
# Joei3/2z2vRz8wD7KRuJGxU+22tSkyvErDmB1zxnV5o5NuAoCJrjOU+biQl/e8Vh
# f1mJMiUKaq4aPvCiJ6i2w7iH9xYESEE9XNjsn00gMQTZZaHtzWkHUxY93TYCCojr
# QOUGMAu4Fkvc77xVCf/GPhIudrPczkLv+XZX4bcKBUCYWJpdcRaTcYxlgepv84n3
# +3OttOe/2Y5vqgtPJfO44dXddZhogfiqwNGAwsTEOYnB9smebNd0+dmX+E/CmgrN
# Xo/4GengpZ/E8JIh5i15Jcki+cPwOoRXrToW9GOUEB1d0MYwggWaMIIEgqADAgEC
# AhEA5+9O8chDX2TZpbrTK3TN+zANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJH
# QjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3Jk
# MRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RPIFJT
# QSBDb2RlIFNpZ25pbmcgQ0EwHhcNMTgwOTI1MDAwMDAwWhcNMTkwOTI1MjM1OTU5
# WjCB3jELMAkGA1UEBhMCR0IxETAPBgNVBBEMCENGNDUgNFNOMRowGAYDVQQIDBFS
# aG9uZGRhIEN5bm9uIFRhZjESMBAGA1UEBwwJQWJlcmN5bm9uMScwJQYDVQQJDB5W
# ZW50dXJlIEhvdXNlLCBOYXZpZ2F0aW9uIFBhcmsxKjAoBgNVBAoMIUFzdHJpeCBJ
# bnRlZ3JhdGVkIFN5c3RlbXMgTGltaXRlZDELMAkGA1UECwwCSVQxKjAoBgNVBAMM
# IUFzdHJpeCBJbnRlZ3JhdGVkIFN5c3RlbXMgTGltaXRlZDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAO0miT1vPgd4HI8wZFQZeX/WkRhGW4tJbidMxVUr
# dEzjohmiAT8U1igUhltAaypUd2em5OWs90lypNEV85Xg9dvfZA+Uz8Jg2YenyV6k
# Yvfcz6ckzh2A3UudbYVoeLlhj5H5WvvPoiVB0a+pP5p/wEZ8diz125Dii7fpsQNX
# niE1dIB+6BYCDkBs2NG+5riEyjK2bizO+VE3EBs0H4XAtoAOomFhhd4YuZCTZFvw
# mGyCWqqYRHoEk9g4iJhpaiqaafjNbtudDUCxlwz+JUX23VMmlZHfM2McIidKGBF5
# eUzpnlXZBXb3Gw2TI5XXbqHIR6XbIHvo7PthqopmL1nmrSkCAwEAAaOCAbEwggGt
# MB8GA1UdIwQYMBaAFCmRYP+KTfrr+aZquM/55ku9Sc4SMB0GA1UdDgQWBBQ/9Ss6
# 0a6UZaeK59pJH7hks1zNyzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAT
# BgNVHSUEDDAKBggrBgEFBQcDAzARBglghkgBhvhCAQEEBAMCBBAwRgYDVR0gBD8w
# PTA7BgwrBgEEAbIxAQIBAwIwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUu
# Y29tb2RvLm5ldC9DUFMwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQ09NT0RPUlNBQ29kZVNpZ25pbmdDQS5jcmwwdAYIKwYBBQUHAQEE
# aDBmMD4GCCsGAQUFBzAChjJodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9S
# U0FDb2RlU2lnbmluZ0NBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29t
# b2RvY2EuY29tMCIGA1UdEQQbMBmBF2Jlbi5ob29wZXJAYXN0cml4LmNvLnVrMA0G
# CSqGSIb3DQEBCwUAA4IBAQAo/i6qoDQOLeeuRT1jPRa4FxEgeVIwIxMEOGBhYYq4
# DGrgcIei1zWNy7/6gAhG07TLxeYUaykMC/iQmwzfXAyfFSyZm6OmHYKZvTiuPE80
# v+A9FZG17Q2QpAoYpCbnqlUWW/U7QMMIx5s9WXmqCXGzzNX5RgPZ4P5+EdyLytF2
# LcaOoMwm6IMbalBHZXCxocDmw0C0aU3CiaJp3ThnNwzkrrxB2+8Al+NgilVhN37s
# DkkZ3UAYesFAmpzToPAxeTCooIRFqCVbKVGFJAowL+GKwUQIPE9St/+MnqcLEwmA
# BFA//r3ppWICmA7MDk9jR9rz4mb/ErrvMCocccA7wCwsMIIF4DCCA8igAwIBAgIQ
# LnyHzA6TSlL+lP0ct800rzANBgkqhkiG9w0BAQwFADCBhTELMAkGA1UEBhMCR0Ix
# GzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEa
# MBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0Eg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTMwNTA5MDAwMDAwWhcNMjgwNTA4
# MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRl
# ZDEjMCEGA1UEAxMaQ09NT0RPIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmmJBjd5E0f4rR3elnMRHrzB79MR2zuWJX
# P5O8W+OfHiQyESdrvFGRp8+eniWzX4GoGA8dHiAwDvthe4YJs+P9omidHCydv3Lj
# 5HWg5TUjjsmK7hoMZMfYQqF7tVIDSzqwjiNLS2PgIpQ3e9V5kAoUGFEs5v7BEvAc
# P2FhCoyi3PbDMKrNKBh1SMF5WgjNu4xVjPfUdpA6M0ZQc5hc9IVKaw+A3V7Wvf2p
# L8Al9fl4141fEMJEVTyQPDFGy3CuB6kK46/BAW+QGiPiXzjbxghdR7ODQfAuADcU
# uRKqeZJSzYcPe9hiKaR+ML0btYxytEjy4+gh+V5MYnmLAgaff9ULAgMBAAGjggFR
# MIIBTTAfBgNVHSMEGDAWgBS7r34CPfqm8TyEjq3uOJjs2TIy1DAdBgNVHQ4EFgQU
# KZFg/4pN+uv5pmq4z/nmS71JzhIwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYDVR0gBAowCDAGBgRVHSAA
# MEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9E
# T1JTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHEGCCsGAQUFBwEBBGUwYzA7
# BggrBgEFBQcwAoYvaHR0cDovL2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQWRk
# VHJ1c3RDQS5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNv
# bTANBgkqhkiG9w0BAQwFAAOCAgEAAj8COcPu+Mo7id4MbU2x8U6ST6/COCwEzMVj
# EasJY6+rotcCP8xvGcM91hoIlP8l2KmIpysQGuCbsQciGlEcOtTh6Qm/5iR0rx57
# FjFuI+9UUS1SAuJ1CAVM8bdR4VEAxof2bO4QRHZXavHfWGshqknUfDdOvf+2dVRA
# GDZXZxHNTwLk/vPa/HUX2+y392UJI0kfQ1eD6n4gd2HITfK7ZU2o94VFB696aSdl
# kClAi997OlE5jKgfcHmtbUIgos8MbAOMTM1zB5TnWo46BLqioXwfy2M6FafUFRun
# UkcyqfS/ZEfRqh9TTjIwc8Jvt3iCnVz/RrtrIh2IC/gbqjSm/Iz13X9ljIwxVzHQ
# NuxHoc/Li6jvHBhYxQZ3ykubUa9MCEp6j+KjUuKOjswm5LLY5TjCqO3GgZw1a6lY
# YUoKl7RLQrZVnb6Z53BtWfhtKgx/GWBfDJqIbDCsUgmQFhv/K53b0CDKieoofjKO
# Gd97SDMe12X4rsn4gxSTdn1k0I7OvjV9/3IxTZ+evR5sL6iPDAZQ+4wns3bJ9ObX
# wzTijIchhmH+v1V04SF3AwpobLvkyanmz1kl63zsRQ55ZmjoIs2475iFTZYRPAmK
# 0H+8KCgT+2rKVI2SXM3CZZgGns5IW9S1N5NGQXwH3c/6Q++6Z2H/fUnguzB9XIDj
# 5hY5S6cxggR7MIIEdwIBATCBkjB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
# YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01P
# RE8gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RPIFJTQSBDb2RlIFNpZ25pbmcg
# Q0ECEQDn707xyENfZNmlutMrdM37MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQH9CCNsF8NajXZ
# Z25kPqS1I5bHpjANBgkqhkiG9w0BAQEFAASCAQAIW3XTapAEd8DJAMmqSSAVaMif
# tbrfUxcW6EwmBXM7qjCmMYtFLfF0iUOGcxbgAmAB/qWhZajnyT6NToTRc/u41peP
# 05QU9CxP9x61Wd76TtBeDMuGwLzkAH6cjdD8jD1cRCazIkR7XhdgefzDWPOifAp/
# S/ayDTPVBd2N7xlpPpJD9O3amhlcF6WRzc84s+r3X7mw1/4kjps2FqO3PvDKsvwK
# QB6B2Cox9vp4La0RWbDY/Zqr4a86SEi7bt5Ayoz0FeenEgui4DaR3Wvw/Xnt7oeq
# 4GH/XFEhGu5l1SuAJBWlXRFV6M9dK4JJCC3l42hq4qy/Mp+VPrEzYk0zUdMNoYIC
# QzCCAj8GCSqGSIb3DQEJBjGCAjAwggIsAgEBMIGpMIGVMQswCQYDVQQGEwJVUzEL
# MAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRy
# dXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJGaXJzdC1PYmplY3QCDxaI8DklXmOO
# aRQ5B+YzCzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgxMDE1MDk0MjUwWjAjBgkqhkiG9w0BCQQxFgQUjQCN
# spPqjZwMeuQ19DEujwq62v0wDQYJKoZIhvcNAQEBBQAEggEAYfAH6eoRUxIdSgQM
# zMcwkva9Hsw3OJq8rsPZZzZTvxtYxKY+8+ewv+8uwdt0V8kNCY9G+6igs2hWxSg/
# 1EA3U2MUzh5aUd9fRO4sIq4h+f1NZ73ZHjEMFCUslhQC5rRPTsTHYg7FB/Ge+2il
# ndpHna8yzGofSNqnS/nym200/voV7c+FlZz7dHbnVwzKPGuzZUXcqgLE81fdmw/W
# cm6kHLykuIwKfEuMhBiYafSoNIxY7ELuXjGZ8JYOR6g2JliwNiMRqYDJfvkjOYHh
# 40J2y4/JChKCukzoeHHE2qa875uTpHSHJQNInb+yTMdHiKzHlSDm2nFZUf1F19l3
# G9KFhQ==
# SIG # End signature block
