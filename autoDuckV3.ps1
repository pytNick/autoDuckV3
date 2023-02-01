function Show-MainMenu {
	param (
		
	)
	Clear-Host
	Write-Host -NoNewLine -ForegroundColor Green 'Username: '
	Write-Host $env:USERNAME
	Write-Host -NoNewLine -ForegroundColor Green 'Computername: '
	Write-Host $env:COMPUTERNAME
	Write-Host -NoNewLine -ForegroundColor Green 'Windows Edition: '
	Get-WmiObject win32_operatingsystem | ForEach-Object caption
	Write-Host -NoNewLine -ForegroundColor Green 'Windows Version: '
	(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId
	
	Write-Host @"

===== Options: =====
	1) Show Network Information
	2) Set Background
	3) Set Lockscreen
	4) Prepare Directory
	5) Install Default Programs
	6) Install Office
	7) Set File associations
	8) Set Explorer view settings
	...
	0) User Scripts
	...
	q) Quit
 
"@
}

function Download-Resources {
	param (
		
	)
	Clear-Host
	if(!(Test-Path C:\SippicomInstall)) {
		mkdir C:\SippicomInstall
	}
	if(!(Test-Path C:\SippicomInstall\assoc)) {
		mkdir C:\SippicomInstall\assoc
	}
	$ProgressPreference = 'silentlyContinue'
	Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Setups.zip -OutFile C:\SippicomInstall\Setups.zip
	Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/SetUserFTA.exe -OutFile C:\SippicomInstall\SetUserFTA.exe
	Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Acroassoc.txt -OutFile C:\SippicomInstall\assoc\Acroassoc.txt
	Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Officeassoc.txt -OutFile C:\SippicomInstall\assoc\Officeassoc.txt
	Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/VLCassoc.txt -OutFile C:\SippicomInstall\assoc\VLCassoc.txt
	Expand-Archive -LiteralPath C:\SippicomInstall\Setups.zip -DestinationPath C:\SippicomInstall -Force
	Remove-Item C:\SippicomInstall\Setups.zip
	
	Clear-Host
	Write-Host -BackgroundColor Green -ForegroundColor White "Done!"
}

function Install-DefaultPrograms {
	param (
		
	)
	Start-Process msiexec.exe -ArgumentList "-i C:\SippicomInstall\7zip.msi -qn" -Wait
	Write-Host -BackgroundColor Green -ForegroundColor White "7-Zip installation done!"
	Start-Process msiexec.exe -ArgumentList "-i C:\SippicomInstall\VLC.msi -qn" -Wait
	if(!(Test-Path C:\SippicomInstall\assoc\VLCassoc.txt)) {
		Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/VLCassoc.txt -OutFile C:\SippicomInstall\assoc\VLCassoc.txt
	}
	C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\VLCassoc.txt
	Write-Host -BackgroundColor Green -ForegroundColor White "VLC installation done!"
	Start-Process C:\SippicomInstall\readerdc_de_xa_crd_install.exe -Wait
	if(!(Test-Path C:\SippicomInstall\assoc\Acroassoc.txt)) {
		Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Acroassoc.txt -OutFile C:\SippicomInstall\assoc\Acroassoc.txt
	}
	C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\Acroassoc.txt
	Write-Host -BackgroundColor Green -ForegroundColor White "Acrobat Reader installation done!"
	Write-Host -BackgroundColor Green -ForegroundColor White "All done!"
}

function Show-UserScriptsMenu {
	param (
		
	)
	Write-Host @"

===== Options: =====
	1) Nico
	2) Nick
	...
	q) Quit
"@
}

do {
	Show-MainMenu
	$key = $Host.UI.RawUI.ReadKey()
	switch ($key.Character) {
		'1' {
			Clear-Host
			Get-NetIPConfiguration |
			Where-Object {$_.InterfaceAlias -notlike '*Bluetooth*' -and $_.InterfaceAlias -notlike '*Virtual*' } |
			Select-Object @{Name='<==================';Expression={}},@{Name='Interface';Expression={$_.InterfaceAlias}},@{Name='IP';Expression={$_.IPv4Address}},@{Name='Gateway';Expression={$_.IPv4DefaultGateway.NextHop}},@{Name='DNS';Expression={$_.DNSServer.ServerAddresses}},@{Name='==================>';Expression={}}
		}
		'2' {
			Clear-Host
			$imgURL = "https://imgur.com/cRJzKUS.jpg"
			New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value 0 -Force
			New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
			Add-Type -TypeDefinition "using System;`nusing System.Runtime.InteropServices;`npublic class Params`n{`n[DllImport(`"User32.dll`",CharSet=CharSet.Unicode)]`npublic static extern int SystemParametersInfo (Int32 uAction,`nInt32 uParam,`nString lpvParam,`nInt32 fuWinIni);`n}`n".ToString()
			Invoke-WebRequest -Uri $imgURL -OutFile $env:TEMP\PSWallpaper.jpg
			[Params]::SystemParametersInfo(0x0014, 0, "$env:TEMP\PSWallpaper.jpg", (0x01 -bor 0x02))
			
			Clear-Host
			Write-Host -BackgroundColor Green -ForegroundColor White "Done!"
		}
		'3' {
			Clear-Host
			$imgURL = "https://imgur.com/TUwv8kH.jpg"
			Invoke-WebRequest -Uri $imgURL -OutFile $env:TEMP\PSLockScreenWallpaper.jpg
			Copy-Item $env:TEMP\PSLockScreenWallpaper.jpg "C:\Windows\System32\LockScreen.jpg" -Force
			New-Item -Path "REGISTRY::HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Force | Out-Null
			New-ItemProperty -Path "REGISTRY::HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageStatus" -Value "1" -PropertyType DWORD -Force | Out-Null
        	New-ItemProperty -Path "REGISTRY::HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Value C:\Windows\System32\LockScreen.jpg -PropertyType STRING -Force | Out-Null
        	New-ItemProperty -Path "REGISTRY::HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageUrl" -Value C:\Windows\System32\LockScreen.jpg -PropertyType STRING -Force | Out-Null
		}
		'4' {
			Download-Resources
		}
		'5' {
			Clear-Host
			if(!(Test-Path C:\SippicomInstall\7zip.msi) -Or !(Test-Path C:\SippicomInstall\VLC.msi) -Or !(Test-Path C:\SippicomInstall\readerdc64_de_hi_mdr_install.exe)) {
				Download-Resources
			}
			Install-DefaultPrograms
		}
		'6' {
			Clear-Host
			if(!(Test-Path C:\SippicomInstall\OfficeSetup.exe)) {
				Download-Resources
			}
			Start-Process C:\SippicomInstall\OfficeSetup.exe -Wait
			if(!(Test-Path C:\SippicomInstall\assoc\Officeassoc.txt)) {
				Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Officeassoc.txt -OutFile C:\SippicomInstall\assoc\Officeassoc.txt
			}
			C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\Officeassoc.txt
			
			Clear-Host
			Write-Host -BackgroundColor Green -ForegroundColor White "Office installation done!"
		}
		'7' {
			Clear-Host
			if(!(Test-Path C:\SippicomInstall\assoc)) {
				mkdir C:\SippicomInstall\assoc
			}
			if(!(Test-Path C:\SippicomInstall\assoc\VLCassoc.txt)) {
				Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/VLCassoc.txt -OutFile C:\SippicomInstall\assoc\VLCassoc.txt
			}
			C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\VLCassoc.txt
			if(!(Test-Path C:\SippicomInstall\assoc\Acroassoc.txt)) {
				Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Acroassoc.txt -OutFile C:\SippicomInstall\assoc\Acroassoc.txt
			}
			C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\Acroassoc.txt
			if(!(Test-Path C:\SippicomInstall\assoc\Officeassoc.txt)) {
				Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/Officeassoc.txt -OutFile C:\SippicomInstall\assoc\Officeassoc.txt
			}
			C:\SippicomInstall\SetUserFTA.exe C:\SippicomInstall\assoc\Officeassoc.txt
			
			Write-Host "Do you want to make these the default file associations for every user on this device? (y/n)"
			$qKey = $Host.UI.RawUI.ReadKey()
			switch ($qKey.Character) {
				'y' {
					if(!(Test-Path C:\SippicomInstall\assoc\assoc.bat)) {
						Invoke-WebRequest https://github.com/pytNick/autoDuckV3/raw/FunkyMonkey/resources/assoc.bat -OutFile C:\SippicomInstall\assoc\assoc.bat
					}
					Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name '!SetAssociations' -Value "C:\SippicomInstall\assoc\assoc.bat"
					Break;
				}
				'n' {
					Break;
				}
			}

			Clear-Host
			Write-Host -BackgroundColor Green -ForegroundColor White "File associations set!"
		}
		'8' {
			Clear-Host
			Get-PSDrive -PSProvider Registry

			Set-ItemProperty -Type DWord -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -value "0"
			Set-ItemProperty -Type DWord -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -value "1"
			Set-ItemProperty -Type DWord -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -value "1"
			Set-ItemProperty -Type DWord -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -value "1"

			Set-ItemProperty -Type DWord -Path HKCU:\SOFTWARE\Classes\CLSID\`{031E4825-7B94-4dc3-B131-E946B44C8DD5`} -Name System.IsPinnedToNameSpaceTree -value "1"

			taskkill /f /im explorer.exe
			start explorer.exe
			Clear-Host
			Write-Host -BackgroundColor Green -ForegroundColor White "Explorer view settings done!"
		}
		'9' {
			Clear-Host
		}
		'0' {
			Clear-Host
			Show-UserScriptsMenu
			do {
					$uKey = $Host.UI.RawUI.ReadKey()
					switch ($uKey.Character) {
						'1' {
							Clear-Host
						}
						'2' {
							Clear-Host
							Invoke-WebRequest https://raw.githubusercontent.com/pytNick/autoDuckV3NicK/FunkyMonkey/run.ps1 -OutFile $env:TEMP\nick.ps1
							& {Start-Process PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $env:TEMP\nick.ps1" -Verb RunAs}
						}
					}
				} until ($uKey.Character -eq 'q')
			}
		}
		pause
} until($key.Character -eq 'q')
