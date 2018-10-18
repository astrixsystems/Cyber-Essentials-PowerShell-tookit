<#
.SYNOPSIS
	Name: Enable-WindowsFirewall.ps1
	The purpose of this script is to enable Windows Firewall.
	
.DESCRIPTION
	The purpose of this script is to enable Windows Defender Firewall in order to comply with Cyber Essentials Plus.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Enable-WindowsFirewall.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.NOTES
	Author:				Ben Hooper at Astrix
	Created:			2018/09/06
	Tested on:			Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Updated:			2018/09/11
	Version:			1.1
	Changes in v1.1:	Added detection and reporting of current network profile states.

.EXAMPLE
	Run with the default settings:
		Enable-WindowsFirewall
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Enable-WindowsFirewall -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Enable-WindowsFirewall -LogOutput -LogPath "C:\$env:computername.Enable-WindowsFirewall.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Enable-WindowsFirewall -LogOutput -LogPath "\\servername\filesharename\$env:computername.Enable-WindowsFirewall.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$LogPath_Default = "C:\$env:computername.Enable-WindowsFirewall.txt";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Enable-WindowsFirewall {
	Param()
	
	Begin {
		Write-Output "Enabling Windows Defender Firewall for all network profiles...";
		Write-Output "";
	}
	
	Process {
		Try {
			Write-Output "`t Checking Windows service...";
			$WindowsFirewall_Service = Get-Service "MpsSvc";
			$WindowsFirewall_StartupType = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='MpsSvc'" | Select-Object -ExpandProperty StartMode;
			
			If ($WindowsFirewall_StartupType -Eq "Auto"){
				Write-Output "`t `t ...Startup type is already set to automatic.";
			} Else {
				Write-Output "`t `t ...Startup type is NOT set to automatic. Setting...";
				
				Try {
					Set-Service $WindowsFirewall_Service.Name -StartupType Automatic;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			}
			
			Write-Output "";
			
			If ($WindowsFirewall_Service.Status -Eq "Stopped"){
				Write-Output "`t `t ...Status is set to stopped. Starting...";
				Try {
					Start-Service $WindowsFirewall_Service.Name;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			} ElseIf ($WindowsFirewall_Service.Status -Eq "Running"){
				Write-Output "`t `t ...Status is already running.";
			}
				
			Write-Output "";
			
			Write-Output "`t Checking network profiles' states...";
			$WindowsFirewall_Profile_Domain_State = netsh advfirewall show domainprofile state;
			$WindowsFirewall_Profile_Private_State = netsh advfirewall show privateprofile state;
			$WindowsFirewall_Profile_Public_State = netsh advfirewall show publicprofile state;
			
			If ($WindowsFirewall_Profile_Domain_State -Like "*ON*"){
				Write-Output "`t `t ...Domain profile state is already set to on.";
			} Else{
				Write-Output "`t `t ...Domain profile state is NOT set to on. Setting...";
				
				Try {
					netsh advfirewall set domainprofile state on | Out-Null;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			}
				
			Write-Output "";
			
			If ($WindowsFirewall_Profile_Private_State -Like "*ON*"){
				Write-Output "`t `t ...Private profile state is already set to on.";
			} Else{
				Write-Output "`t `t ...Private profile state is NOT set to on. Setting...";
				
				Try {
					netsh advfirewall set privateprofile state on | Out-Null;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			}
				
			Write-Output "";
			
			If ($WindowsFirewall_Profile_Public_State -Like "*ON*"){
				Write-Output "`t `t ...Public profile state is already set to on.";
			} Else{
				Write-Output "`t `t ...Public profile state is NOT set to on. Setting...";
				
				Try {
					netsh advfirewall set publicprofile state on | Out-Null;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			}
				
			Write-Output "";
			
			Write-Output "`t Setting default connection behaviour for all network profiles...";
			Try {
				netsh advfirewall set allprofiles firewallpolicy "blockinbound,allowoutbound" | Out-Null;
			}
			Catch {
				Write-Output "`t `t ...FAILURE. Exiting...";
				
				Break;
			}
			If($?){
				Write-Output "`t `t ...Success.";
			}
		}
		
		Catch {
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

Write-Output "This script requires administrative permissions. Checking...";
Write-Output "";
If ($RunAsAdministrator -Eq $False) {
	Write-Output "`t This script was NOT run as administrator. Exiting...";
	
	Break;
} ElseIf ($RunAsAdministrator -Eq $True) {
	Write-Output "`t This script WAS run as administrator. Proceeding...";
	Write-Output "";
	
	Enable-WindowsFirewall;
	
	Write-Output "";
	Write-Output "Script complete. Exiting...";
}

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIVMAYJKoZIhvcNAQcCoIIVITCCFR0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUL7UCozYHWodnc/cB1HA+xo+
# 9QqgghAfMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT00w7bBD7H6w1t
# O3Zn3JQQ4WfXRjANBgkqhkiG9w0BAQEFAASCAQB8ivhBgip1evpsdg8z5TN3FDza
# Ux+rBUhAhKDgG79cjcJQ9hadeHxJQDaTVTudj9osA4lfc4WByDrnUlcVQdv3h2Q9
# Wjq4AoRsdQBSDMqwAj+vKJC7TISHeoxQSmgQYs0pULALTLY4PQWhlEYJVaOwX2QM
# OC/J7/HfRgJG7LgPOyTWPYtZJ/eRCfMpIY6+Fu2VnZZymLHPSXK1E+yfg1HtfUlC
# XCNyz9r51QUEk0e8Ldez4cZ5+7HYR34Qli2O8EbCWYg/zbDFXzJM9c0/RjSi6vyE
# oSQvzXAUHsJcgmCauf+B0cXOqUiFCZXS0wr25zFYgIgY9Qk879FbStsrT+kKoYIC
# QzCCAj8GCSqGSIb3DQEJBjGCAjAwggIsAgEBMIGpMIGVMQswCQYDVQQGEwJVUzEL
# MAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRy
# dXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJGaXJzdC1PYmplY3QCDxaI8DklXmOO
# aRQ5B+YzCzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgwOTI1MDgyNTEyWjAjBgkqhkiG9w0BCQQxFgQUHMjG
# RHHwjo7UGeHEp/VAEJexWkgwDQYJKoZIhvcNAQEBBQAEggEA0xsOQDFAKEn/slFP
# i28XAOOP+ToDelMmr6oVhpOLDbi210V3uBI+vMktv4qN8le6CnmPq+KoXRIIMAAH
# Rs1AsL/e40G4zZbP7TA9JaDzus0ieRg1oEzlE0m16jhAT/6NUM/zpGFQIjnALmQb
# 3Nv+ETLkO0VCwGNNLkhvX6LZaIsdIxIVvBG/7u7jFf1OfhTy56hlB9HLmyjH0XtX
# DehA4h+Vnk1M8Nh+ybWHA6WNQgvDeFT49/nXOP/vPOdylnFRjy/kTGkpdfH9cDva
# UM5VB2Wz/B3afyKDuiCIe6sNIdBqMXU0hn/ikEap78G6LMrjTAfY68MlUnzpJWlP
# rpPh6Q==
# SIG # End signature block
