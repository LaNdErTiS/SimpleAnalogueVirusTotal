rule screenshot : T1113 {
    meta:
        description = "Takes screenshot"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt"
        $c2 = "GetDC"
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule  run_entry : T1060
{
    meta:
        description = "Registry Run Keys or Startup Folder"
    strings:
        $a0 = "(HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $a1 = "(HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $a2 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $a3 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $a4 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" nocase wide ascii
        $a5 = "RegSetValueExA" nocase wide ascii

    condition:
        ($a0 or $a1 or $a2 or $a3 or $a4) and $a5
}

rule inject_remote_thread : T1055 {
    meta:
        description = "Code injection with CreateRemoteThread"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}

rule  cmd : T1059
{
    meta:
        description = "CLI"
    strings:
        $a0 = "cmd.exe" nocase wide ascii

    condition:
        any of them
}

rule  token_impersonation : T1134
{
	meta:
		description = "Access Token Manipulation"
	strings:
		$s0 = "ImpersonateLoggedOnUser" wide ascii
		$s1 = "SetThreadToken" wide ascii

	condition:
		all of them
}

rule  application_windows_discovery : T1010
{
    meta:
        description = "Enumerate windows and child window"
    strings:
        $s0 = "EnumWindows"
        $s1 = "GetForegroundWindow"
        $s2 = "GetWindowText"
        $s3 = "GetActiveWindowTitle"

    condition:
        ( $s1 and $s2 ) or $s0 or $s3
}

rule  input_capture : T1056
{
    meta:
        description = "Capturing user input to obtain credentials or collect information"
    strings:
        $s0 = "SetWindowsHook"
        $s1 = "GetKeyState"
        $s2 = "GetAsyncKeyState"
    condition:
        $s0 or $s1 or $s2
}

rule  BITS_CLSID : T1197
{
    meta:
        description = "References the BITS service."
        author = "Ivan Kwiatkowski (@JusticeRage)"
        // The BITS service seems to be used heavily by EquationGroup.
    strings:
        $uuid_background_copy_manager_1_5 =     { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
        $uuid_background_copy_manager_2_0 =     { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
        $uuid_background_copy_manager_2_5 =     { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
        $uuid_background_copy_manager_3_0 =     { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_manager_4_0 =     { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
        $uuid_background_copy_manager_5_0 =     { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
        $uuid_background_copy_manager =         { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
        $uuid_ibackground_copy_manager =        { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
        $uuid_background_copy_qmanager =        { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
        $uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_callback =        { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }
    condition:
        any of them
}

rule  Base64d_PE : T1027
{
	meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"

	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

	condition:
		any of them
}

rule  RijnDael_AES : T1573
{	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}