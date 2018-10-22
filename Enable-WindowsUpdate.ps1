<#
.SYNOPSIS
	Name: Enable-WindowsUpdate.ps1
	The purpose of this script is to enable Windows Update.
	
.DESCRIPTION
	The purpose of this script is to enable Windows Update in order to comply with Cyber Essentials Plus.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Enable-WindowsUpdate.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.NOTES
	Author:				Ben Hooper at Astrix
	Created:			2018/09/11
	Tested on:			Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Updated:			2018/09/20
	Version:			1.3
	Changes in v1.3:	Corrected some hyphen characters from "–"(U+00E2 / U+0080 / U+0093 / U+2013) to "-" (U+002D).
	Changes in v1.2:	Changed configuration of Windows Update from COM objects to Registry.
	Changes in v1.1:	Added configuration of Windows Update settings.

.EXAMPLE
	Run with the default settings:
		Enable-WindowsUpdate
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Enable-WindowsUpdate -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Enable-WindowsUpdate -LogOutput -LogPath "C:\$env:computername.Enable-WindowsUpdate.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Enable-WindowsUpdate -LogOutput -LogPath "\\servername\filesharename\$env:computername.Enable-WindowsUpdate.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$LogPath_Default = "C:\$env:computername.Enable-WindowsUpdate.txt";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Enable-WindowsUpdate {
	Param()
	
	Begin {
		Write-Output "Enabling Windows Update...";
		Write-Output "";
	}
	
	Process {
		Try {
			Write-Output "`t Checking Windows service...";
			$WindowsUpdate_Service = Get-Service "wuauserv";
			$WindowsUpdate_StartupType = Get-WmiObject -Class Win32_Service -Property StartMode -Filter "Name='wuauserv'" | Select-Object -ExpandProperty StartMode;
			
			If ($WindowsUpdate_StartupType -Eq "Auto"){
				Write-Output "`t `t ...Startup type is already set to automatic.";
			} Else {
				Write-Output "`t `t ...Startup type is NOT set to automatic. Setting...";
				
				Try {
					Set-Service $WindowsUpdate_Service.Name -StartupType Automatic;
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
			
			If ($WindowsUpdate_Service.Status -Eq "Stopped"){
				Write-Output "`t `t ...Status is set to stopped. Starting...";
				Try {
					Start-Service $WindowsUpdate_Service.Name;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			} ElseIf ($WindowsUpdate_Service.Status -Eq "Running"){
				Write-Output "`t `t ...Status is already running.";
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

Function Configure-WindowsUpdate {
	Param()
	
	Begin {
		Write-Output "Configuring Windows Update...";
		Write-Output "";
	}
	
	Process {
		Try {
			$WindowsUpdate_RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU";
			$WindowsUpdate = New-Object -ComObject "Microsoft.Update.AutoUpdate";
			$WindowsUpdate_Settings = $WindowsUpdate.Settings;
			
			Write-Output "`t Enabling Windows Update...";
			
			Try {
				If (-Not (Test-Path $WindowsUpdate_RegistryPath)){
					New-Item -Path $WindowsUpdate_RegistryPath -Force | Out-Null;
				}
				
				Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "NoAutoUpdate" -Type DWORD -Value "0" -Force;
			}
			Catch {
				Write-Output "`t `t ...FAILURE. Exiting...";
				
				Break;
			}
			If($?){
				Write-Output "`t `t ...Success.";
			}
			
			Write-Output "";
			
			Write-Output "`t Checking Important Updates configuration...";
			
			If ($WindowsUpdate_Settings.NotificationLevel -Eq 1) {
				Write-Output "`t `t ...Currently set to ""Never check for updates (not recommended)"".";
			} ElseIf ($WindowsUpdate_Settings.NotificationLevel -Eq 2) {
				Write-Output "`t `t ...Currently set to ""Check for updates but let me choose whether to download and install them"".";
			} ElseIf ($WindowsUpdate_Settings.NotificationLevel -Eq 3) {
				Write-Output "`t `t ...Currently set to ""Download updates but let me choose whether to install them"".";
			} ElseIf ($WindowsUpdate_Settings.NotificationLevel -Eq 4) {
				Write-Output "`t `t ...Currently set to ""Install updates automatically (recommended)"".";
			}
			
			Write-Output "";
			
			Write-Output "`t `t Setting to ""Install updates automatically (recommended)""...";
			
			Try {
				Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "AUOptions" -Type DWORD -Value "4" -Force;
			}
			Catch {
				Write-Output "`t `t ...FAILURE. Exiting...";
				
				Break;
			}
			If($?){
				Write-Output "`t `t ...Success.";
			}
		
			Write-Output "";
			
			Write-Output "`t Checking Recommended Updates configuration...";
			
			If ($WindowsUpdate_Settings.IncludeRecommendedUpdates -Eq $False) {
				Write-Output "`t `t ...Currently set to disabled. ";
				Write-Output "";
				Write-Output "`t `t Setting to enabled...";
				
				Try {
					Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "AutoInstallMinorUpdates" -Type DWORD -Value "0" -Force;
					Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "IncludeRecommendedUpdates" -Type DWORD -Value "1" -Force;
				}
				Catch {
					Write-Output "`t `t ...FAILURE. Exiting...";
					
					Break;
				}
				If($?){
					Write-Output "`t `t ...Success.";
				}
			} ElseIf ($WindowsUpdate_Settings.IncludeRecommendedUpdates -Eq $True) {
				Write-Output "`t `t ...Set to enabled.";
			}
			
			Write-Output "";
			
			Write-Output "`t Setting Windows Update to update other Microsoft products...";
			
			Try {
				Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "AllowMUUpdateService" -Type DWORD -Value "1" -Force;
				
				$MicrosoftUpdateServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager";
				$MicrosoftUpdateServiceManager.ClientApplicationID = "My App";
				$MicrosoftUpdateServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") | Out-Null;
			}
			Catch {
				Write-Output "`t `t ...FAILURE. Exiting...";
				
				Break;
			}
			If($?){
				Write-Output "`t `t ...Success.";
			}
			
			Write-Output "";
			
			Write-Output "`t Setting installation schedule to default ""Every day at 03:00"".";
			
			Try {
				Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "ScheduledInstallDay" -Type DWORD -Value "0" -Force;
				Set-ItemProperty -Path $WindowsUpdate_RegistryPath -Name "ScheduledInstallTime" -Type DWORD -Value "3" -Force;
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
	
	Enable-WindowsUpdate;
	
	Write-Output "";
	
	Configure-WindowsUpdate;
	
	Write-Output "";
	Write-Output "Script complete. Exiting...";
}

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIVMAYJKoZIhvcNAQcCoIIVITCCFR0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUafDjNu8Nf8f13omzDGkbjEOj
# EzmgghAfMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQeV1YYeNhcy7HF
# IOtYmnK6+jB2rDANBgkqhkiG9w0BAQEFAASCAQBtZVeomlX+7u3IeH0Jsy79n0IP
# KETX++imqzoWvhy6bdvzySPnEplhCq6kwX9tQJZvuSfDRSVLxljzetsc8Phs5t5R
# HBCJNvUh/js3fDg1DjwLvvys8fWSop7ZpOcePxvcM6K4/2msGAvAykIbPKeXWHTs
# gwFZwCWx/t6Y2McenJmYpIkk5pqMzTUgp4ooeNQcl0WiLYjpZ5Yh5+40xUNdSq1q
# kEw0Nmf7k17qZ/P9geNOLIP0k6W+A/EmYNHJpEB9vkELrwUWd6QIg4igzNSbAJvJ
# zo9BTGQNSNui6NHC24CirE7WjseMPtx/D8IP1TIQv/+ryhOqzbXj96ASr+e1oYIC
# QzCCAj8GCSqGSIb3DQEJBjGCAjAwggIsAgEBMIGpMIGVMQswCQYDVQQGEwJVUzEL
# MAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRy
# dXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJGaXJzdC1PYmplY3QCDxaI8DklXmOO
# aRQ5B+YzCzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgxMDIyMDkwNDM1WjAjBgkqhkiG9w0BCQQxFgQUoIDb
# 8RbPk/d15car5yl9mesj+v0wDQYJKoZIhvcNAQEBBQAEggEAHtq6oDMhv+uKOLiC
# cXLo8rndOtsneGmYMxgaD/rB+SChaLZPnf4lJJCcF8LTmgA9YjfWARZzvalJuG1y
# cCRcYNGtLINhYYKpLizjceD67QM5Xf8nbqA2AAJmrAxc23hAXE7C3N/ZU+nEq5X4
# oCHBGB2xX/kh1RUrmZbbvH4kGGINNteXeB6hkMBCRIMymeF79QLisFifT/7jxA4E
# 5dqWCbefCHV1IzNWI3tlJQJYFZQp7qBmveFLdWp6yetZ686jeKIEiQ4SrjsfFe1G
# aBzNQTegzSTx6et+myfJewJeEsltB2BoiZooTD1FOPsJ7H1qnFU6GtAtcC8QtpAc
# YGAgzw==
# SIG # End signature block
