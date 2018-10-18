<#
.SYNOPSIS
	Name: Remove-LocalAdminPermissions.ps1
	The purpose of this script is to selectively remove local administrative permissions.
	
.DESCRIPTION
	The purpose of this script is to remove local administrative permissions from all local user accounts except for "administrator", "Domain Admins", and any others specified in order to comply with Cyber Essentials Plus.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Remove-LocalAdminPermissions.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.
	
.PARAMETER DisableDefaultAdmin
	Disables the local administrative user account "administrator".
	
.PARAMETER AdminWhitelist
	The provided list of user and/or group names will retain their administrative permissions. "Administrator" and "Domain Admins" are whitelisted by default.

.NOTES
	Author:				Ben Hooper at Astrix
	Created:			2018/08/15
	Tested on:			Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Updated:			2018/09/20
	Version:			2.5
	Changes in v2.5:	Added parameter for admin whitelist.
	Changes in v2.4:	Added proper error handling.
	Changes in v2.3:	Added parameter for logging with default or custom paths.
	Changes in v2.2:	Added parameter for disabling of local administrative user account "administrator".
	Changes in v2.1:	Formalised code.
	Changes in v2.0:	Changed from using *-LocalGroup* to ADSI for backwards compatibility with Windows 7's default PowerShell version.

.EXAMPLE
	Run with the default settings:
		Remove-LocalAdminPermissions
	
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Remove-LocalAdminPermissions -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Remove-LocalAdminPermissions -LogOutput -LogPath "C:\$env:computername.Remove-LocalAdminPermissions.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Remove-LocalAdminPermissions -LogOutput -LogPath "\\servername\filesharename\$env:computername.Remove-LocalAdminPermissions.txt"
	
.EXAMPLE 
	Run with the default settings AND the disabling of the local administrative user account "administrator":
		Remove-LocalAdminPermissions -DisableDefaultAdmin
	
.EXAMPLE 
	Run with the default settings AND an admin whitelist:
		Remove-LocalAdminPermissions -AdminWhitelist "ITAdmin", "Backup Admin"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[Switch]$DisableDefaultAdmin,
	[Array]$AdminWhitelist,
	[Switch]$LogOutput,
	[String]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$LogPath_Default = "C:\$env:computername.Get-EndpointProtection.txt";

$LocalAdmins_ToRemain = "Administrator", "Domain Admins";
ForEach ($Admin in $AdminWhitelist){
	$LocalAdmins_ToRemain += $Admin;
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function List-ToRemainAdmins {
	Param()
	
	Begin {
		Write-Output "Getting list of to-remain admins...";
		Write-Output "";
	}
	
	Process {
		Try {
			ForEach ($Admin in $LocalAdmins_ToRemain){
				Write-Output "`t $Admin";
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

Function List-CurrentAdmins {
	Param()
	
	Begin {
		Write-Output "Getting list of current admins...";
		Write-Output "";
	}
	
	Process {
		Try {
			$LocalAdminGroup = [ADSI]("WinNT://$env:computername/Administrators,Group");
			# "$Script:" ensures that $LocalAdmins_Current_Paths can be used outside of this function;
			$Script:LocalAdmins_Current_Paths = $LocalAdminGroup.PSBase.Invoke("Members") | ForEach { $_.GetType().InvokeMember("ADSPath", "GetProperty", $Null, $_, $Null); };
			
			For ($i = 0; $i -NE $LocalAdmins_Current_Paths.Length; $i++){
				$LocalAdmin_Current_Username = $LocalAdmins_Current_Paths[$i].Split("/")[-1];
				
				Write-Output "`t $LocalAdmin_Current_Username";
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

Function Remove-Admins {
	Param()
	
	Begin {
		Write-Output "Removing local administrative permissions...";
		Write-Output "";
	}
	
	Process {
		Try {
			$LocalAdminGroup = [ADSI]("WinNT://$env:computername/Administrators,Group");
			
			For ($i = 0; $i -NE $LocalAdmins_Current_Paths.Length; $i++){
				$Retain = $False;
				
				$LocalAdmin_Current_Path = $LocalAdmins_Current_Paths[$i];
				$LocalAdmin_Current_Username = $LocalAdmin_Current_Path.Split("/")[-1];
				Write-Output "`t Analysing current admin '$LocalAdmin_Current_Username'...";
				
				If ($LocalAdmin_Current_Username -Eq "Administrator"){
					Write-Output "`t `t Checking whether DisableDefaultAdmin specified...";
					
					If ($DisableDefaultAdmin -Eq $True) {
						Write-Output "`t `t `t Found.";
						Write-Output "";
						Write-Output "`t `t `t Disabling...";
						
						$Error.Clear()
						Try {
							$DefaultAdmin = [ADSI]$LocalAdmin_Current_Path;
							$DefaultAdmin.UserFlags = 2;
							$DefaultAdmin.SetInfo();
						} Catch {
							Write-Output "`t `t `t FAILURE.";
						}
						If (!$Error){
							Write-Output "`t `t `t Success.";
						}
					} Else {
						Write-Output "`t `t `t NOT found.";
						Write-Output "";
						Write-Output "`t `t `t No changes will be made to status.";
					}
					
					Write-Output "";
				}
				
				Write-Output "`t `t Checking against list of to-remain admins...";

				
				For ($j = 0; $j -NE $LocalAdmins_ToRemain.Length; $j++){
					$LocalAdmin_ToRemain_Username = $LocalAdmins_ToRemain[$j];
					
					If ($LocalAdmin_Current_Username -NE $LocalAdmin_ToRemain_Username){
						$Retain = $False;
					} ElseIf ($LocalAdmin_Current_Username -Eq $LocalAdmin_ToRemain_Username) {
						$Retain = $True;
						
						Break;
					}
				}
				
				If ($Retain -Eq $False) {
					Write-Output "`t `t `t NOT found.";
					Write-Output "";
					Write-Output "`t `t `t Removing admin permissions...";
					
					$Error.Clear()
					Try {
						$LocalAdminGroup.Remove($LocalAdmin_Current_Path) | Out-Null;
					} Catch {
						Write-Output "`t `t `t FAILURE.";
					}
					If (!$Error){
						Write-Output "`t `t `t Success.";
					}
				} ElseIf ($Retain -Eq $True) {
					Write-Output "`t `t `t Found.";
					Write-Output "";
					Write-Output "`t `t `t No changes will be made to permissions / membership.";
				}
				
				Write-Output "";
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

Write-Output "This script requires administrative permissions. Checking...";
Write-Output "";
If ($RunAsAdministrator -Eq $False) {
	Write-Output "`t This script was NOT run as administrator. Exiting...";
	
	Break;
} ElseIf ($RunAsAdministrator -Eq $True) {
	Write-Output "`t This script WAS run as administrator. Proceeding...";
	Write-Output "";
	
	List-ToRemainAdmins;
	Write-Output "";
	List-CurrentAdmins;
	Write-Output "";
	Remove-Admins;
	
	Write-Output "Script complete. Exiting...";
}

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIVMAYJKoZIhvcNAQcCoIIVITCCFR0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU31lLVYnYGgYMaRCfN2xEYV1Y
# CuygghAfMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSy1dYXaRvCTO0i
# JynrTkf6ektm7TANBgkqhkiG9w0BAQEFAASCAQBAD1zBMNKL5QZkqA+QzABtTDP0
# 2bE74f6UUAugheFaTDf1vtKk66r7rMesx6ouEKrSzC7oCAhqJ/MWnVA1K8DVegUl
# 7hzajswmNXYMcW0FFwayL/207V5S/vlXQuZqx0y+4u1iE64Bl2mQlB1QVQgXEr/e
# 62Qa2S2gZcF1jPDF2CNT41E2EDEKOEBqOZZ44/dn4r3Vlig2C7q4qyRPqEmIKwIA
# NvvAOhrBZL02+Qp9NLH7+GMV83pA/8BS21wKBDpc2Z08qnPlgs2FgJIpuSIgEVTw
# lN+ox8FO4i1sWTUDJkVTdbsPvMFovaWoWcyu/JfUxQu1PlOEvcQD9IWRxNwXoYIC
# QzCCAj8GCSqGSIb3DQEJBjGCAjAwggIsAgEBMIGpMIGVMQswCQYDVQQGEwJVUzEL
# MAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRy
# dXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJGaXJzdC1PYmplY3QCDxaI8DklXmOO
# aRQ5B+YzCzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgwOTI1MDgyNTIyWjAjBgkqhkiG9w0BCQQxFgQUnTS6
# vHn3e71IEa3RxrQgl17tiuEwDQYJKoZIhvcNAQEBBQAEggEAXRP+5GDgJZWpTYFp
# zd7h3LQZrKHmb/jcw76/3oT7HVnOpsKMubeBN1ENmEc6shbCm7sV+j4EZ74xSIJ+
# 7ZR1wr2NUpkBi9yDPPoFnQi+Yx+pDocSgUiJTeb9iam/VwEwf7JxHbgJAMta3ZaT
# 5VE6ArodyfjRIMsMrBN9GR3+9znPTdfphz3vpRprslPqkJp3Eha3SBxnJ0chjwgA
# aKSQNFf3Sbs5iJteTvzjz6+1VoSsGO4N/trG5RJk4QCPVTAqjDYKnmtY74kSy8bN
# ee1fC2mkKO6B5Ojm5nVcuzmyeGBpXAPX4Q5W1/pttC0+sVfMGRPyQCO6eFqNB1M8
# r929bg==
# SIG # End signature block
