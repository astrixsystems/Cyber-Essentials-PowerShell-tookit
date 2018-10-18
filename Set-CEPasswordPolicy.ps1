<#
.SYNOPSIS
	Name: Set-CEPasswordPolicy.ps1
	The purpose of this script is to set a password policy that complies with Cyber Essentials.
	
.DESCRIPTION
	The purpose of this script is to set a password policy that complies with Cyber Essentials which requires that:
		1. Passwords have a minimum length of 8 characters. For this, this script will:
			1a. Configure the local policy "Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy" | "Minimum Password Length".
----------> 1b. DISABLE "Password never expires" and ENABLE "User must change password at next logon" FOR ALL LOCAL USER ACCOUNTS.
			
			This is the only way to be sure that passwords have a minimum length of 8 charcters - by implementing the polcy then getting the users to set new ones. BE AWARE! <----------
		2. Passwords have no maximum length. For this, this script does nothing as there is no policy for this in Windows.
		3. All user accounts be password-protected. For this, this script already takes care of this as part of #1.
		4. All default passwords changed. For this, this script already takes care of this as part of #1.
		
	Cyber Essentials does not require password complexity or expiration.
	
.PARAMETER LogOutput
	Logs the output to the default file path "C:\<hostname>.Set-CEPasswordPolicy.txt".
	
.PARAMETER LogFile
	When used in combination with -LogOutput, logs the output to the custom specified file path.

.NOTES
	Author:				Ben Hooper at Astrix
	Created:			2018/09/11
	Tested on:			Windows 7 Professional 64-bit, Windows 10 Pro 64-bit
	Updated:			2018/09/14
	Version:			1.2
	Changes in v1.2:	Changed behaviour of requiring new passwords to be set from only user accounts that had blank passwords to all user accounts and updated description to explicitly spell this out. 

.EXAMPLE
	Run with the default settings:
		Set-CEPasswordPolicy
		
.EXAMPLE 
	Run with the default settings AND logging to the default path:
		Set-CEPasswordPolicy -LogOutput
	
.EXAMPLE 
	Run with the default settings AND logging to a custom local path:
		Set-CEPasswordPolicy -LogOutput -LogPath "C:\$env:computername.Set-CEPasswordPolicy.txt"
	
.EXAMPLE 
	Run with the default settings AND logging to a custom network path:
		Set-CEPasswordPolicy -LogOutput -LogPath "\\servername\filesharename\$env:computername.Set-CEPasswordPolicy.txt"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Param(
	[switch]$LogOutput,
	[string]$LogPath
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$RunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$LogPath_Default = "C:\$env:computername.Set-CEPasswordPolicy.txt";

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Set-PasswordMinimumLength {
	Param(
		[Parameter(Mandatory=$true)][Int]$Length
	)
	
	Begin {
		Write-Output "Implementing minimum password length of $Length...";
	}
	
	Process {
		Try {			
			$Secedit_CFGFile_Path = [System.IO.Path]::GetTempFileName();
			$Secedit_Path = "$env:SystemRoot\system32\secedit.exe";
			$Secedit_Arguments_Export = "/export /cfg $Secedit_CFGFile_Path /quiet";
			$Secedit_Arguments_Import = "/configure /db $env:SystemRoot\Security\local.sdb /cfg $Secedit_CFGFile_Path /areas SecurityPolicy";
			
			Start-Process -FilePath $Secedit_Path -ArgumentList $Secedit_Arguments_Export -Wait -WindowStyle Hidden;
			
			$SecurityPolicy_Old = Get-Content $Secedit_CFGFile_Path;
			
			$SecurityPolicy_New = $SecurityPolicy_Old -Replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = $Length";
			
			Set-Content -Path $Secedit_CFGFile_Path -Value $SecurityPolicy_New;
			
			Start-Process -FilePath $Secedit_Path -ArgumentList $Secedit_Arguments_Import -Wait -WindowStyle Hidden;
		}
		
		Catch {
			Write-Output "...FAILED.";
			Break;
		}
	}
	
	End {
		If($?){ # only execute if the function was successful.
			Write-Output "...Success.";
		}
	}
}

Function Set-PasswordRequirement {
	Param()
	
	Begin {
		Write-Output "Implementing password requirement for all user accounts...";
		Write-Output "";
	}
	
	Process {
		Try {
			$UserAccounts = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True";
			$UserAccounts_Number = $UserAccounts.Length;
			
			Write-Output "$UserAccounts_Number user accounts found.";
			Write-Output "";
			
			For ($i = 0; $i -NE $UserAccounts.Length; $i++){
				$Username = $UserAccounts[$i].Name;
				Write-Output "Current user account: $Username.";
				
				Write-Output "Disabling ""Password never expires""...";
				$Error.Clear();
				Try {
					$UserAccount = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='$Username'";
					$UserAccount.PasswordExpires=$True;
					$UserAccount.Put() | Out-Null;
				} Catch {
					Write-Output "...FAILED.";
				}
				If (!$error){
					Write-Output "...Success.";
				}
				
				Write-Output "Enabling ""User must change password at next logon""...";
				$Error.Clear();
				Try {
					$UserAccount = [ADSI]"WinNT://$env:computername/$Username"; 
					$UserAccount.PasswordExpired = 1;
					$UserAccount.SetInfo() | Out-Null;
				} Catch {
					Write-Output "...FAILED.";
				}
				If (!$error){
					Write-Output "...Success.";
				}
				
				Write-Output "";
			}
		}
		
		Catch {
			Write-Output "...FAILED implementing password requirement for all user accounts.";
			Break;
		}
	}
	
	End {
		If($?){ # only execute if the function was successful.
			Write-Output "...Success implementing password requirement for all user accounts.";
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
If ($RunAsAdministrator -Eq $False) {
	Write-Output "This script was NOT run as administrator. Exiting...";
	
	Break;
} ElseIf ($RunAsAdministrator -Eq $True) {
	Write-Output "This script WAS run as administrator. Proceeding...";
	
	Write-Output "";
	Write-Output "----------------------------------------------------------------";
	Write-Output "";
	
	# Set-PasswordRequirement needs to be executed BEFORE Set-PasswordMinimumLength because changes can't be made to a user account that has a password less than 8 characters long once the policy has been implemented
	
	Set-PasswordRequirement;
	
	Write-Output "";
	Write-Output "----------------------------------------------------------------";
	Write-Output "";
	
	Set-PasswordMinimumLength -Length 8;
}

Write-Output "";
Write-Output "----------------------------------------------------------------";
Write-Output "";

Write-Output "Script complete. Exiting...";

If ($LogOutput -Eq $True) {
	Stop-Transcript | Out-Null;
}
# SIG # Begin signature block
# MIIVMAYJKoZIhvcNAQcCoIIVITCCFR0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhYOhSKMO2su/hMKdArmeTy5h
# Q96gghAfMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBR/5bPCl2gr9dSs
# G3CSvXTxO/xv0zANBgkqhkiG9w0BAQEFAASCAQAbdwj5DF2FpSEcQSi1vgOJ4JpW
# 5aZLinsmmKknplpsEkDrkRfsKNMiLZ3UgFLm548eABiLKibnBDeT0G7kRxVoK0oR
# u2vMV7gciu/jCAHXwGnY8hoOkUwBI2R8yXDb1j1ZZHzmB3RcbhlxvnjBsjR7KwZM
# VylBzbo2XoPQpDz7WueJb1CnqjTZPF5viipA0h4fMUDX9N06Ja9vJvWtzzGm8rYN
# vtSvNcGdsPFGsVVgWu7L6M7dqmjhcLRjBBaPBR3QbQ6NLIXj9NqxX8fDy1J0ZkaQ
# +hWoNw1Isc6CF4nmY65lhUM6CNTUjAPFRI224u3IcV6KNrkHXQkDNUFg9MYXoYIC
# QzCCAj8GCSqGSIb3DQEJBjGCAjAwggIsAgEBMIGpMIGVMQswCQYDVQQGEwJVUzEL
# MAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRy
# dXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJGaXJzdC1PYmplY3QCDxaI8DklXmOO
# aRQ5B+YzCzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMTgwOTI1MDgyNTI3WjAjBgkqhkiG9w0BCQQxFgQUQFTi
# fXBoXNtmIeAevZHKDMf/JAAwDQYJKoZIhvcNAQEBBQAEggEALqtGANtPs9FRWgcF
# UXnJI5oGAt5Cst4AwEIW9MNPB5+yqyVM0GR3DUke6owaw9+vq+7Tn/G75ZB8sMd8
# 0AO8K+m/ZKfOXJC840luK/yndPVT1RQ6VSiugNCjfgOvEyJif/tg2cmYZG249Q/H
# R7HCRpILTCJWgjcY2zOusuLOhkHg1xN4E2hmB1hF/QbplYk55EDRozKhSihiJDqm
# Wicda3lKROM92t1sSH/daV1q6G9aBHP3XaNcMEMkMB2phSuvlOPWRjO5vfjZpTJM
# QWZp22VjK9vAnKbl36X5yZO55X6tVUI0vUn2L7KHKqh7ZOdB1mVXylPpcc9/N1+D
# d7Bdww==
# SIG # End signature block
