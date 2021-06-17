rule redline_first_stage {
   
   meta:
     
      description = "Rule to detect the RedLine initial binary"
      author = "Thatskriptkid"
      date = "2021-06-17"
      rule_version = "v1"
      malware_type = "stealer/backdoor"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
	  filetype = "Win 32 EXE .NET"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"
      hash = "7B8A4942B286B410F550C3551783CABD1AF865E8B994309955786C3F50575E0C"
      
   strings:
		// 0x0000072C 00            IL_0000: nop
		// 0x0000072D 281B00000A    IL_0001: call      class [mscorlib]System.Text.Encoding [mscorlib]System.Text.Encoding::get_UTF8()
		// 0x00000732 02            IL_0006: ldarg.0
		// 0x00000733 7247000070    IL_0007: ldstr     "ConfigurationIdnElement53832"
		// 0x00000738 7E1800000A    IL_000C: ldsfld    string [mscorlib]System.String::Empty
		// 0x0000073D 6F1900000A    IL_0011: callvirt  instance string [mscorlib]System.String::Replace(string, string)
		// 0x00000742 281A00000A    IL_0016: call      uint8[] [mscorlib]System.Convert::FromBase64String(string)
		// 0x00000747 6F1C00000A    IL_001B: callvirt  instance string [mscorlib]System.Text.Encoding::GetString(uint8[])
		// 0x0000074C 281A00000A    IL_0020: call      uint8[] [mscorlib]System.Convert::FromBase64String(string)
		// 0x00000751 0A            IL_0025: stloc.0
		// 0x00000752 2B00          IL_0026: br.s      IL_0028

		// 0x00000754 06            IL_0028: ldloc.0
		// 0x00000755 2A            IL_0029: ret
		
      $decrypt_payload = { 28 [4] 02 7247000070 7e [4] 6f [4] 28 [4] 6f [4] 28 [4] 0A 2b [1] 06 2a}
	  
	  // part of base 64 string
	  $base64_encoded_payload = "VConfigurationIdnElement53832FZxUUFBTUFBQUFFQUFBQS8vOEFBTGdBQUFBQUFBQUFRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFnQUFBQUE0ZnVnNEF0QW5OSWJnQlRNMGhWR2hwY3lCd2NtOW5jbUZ0SUdOaGJtNXZkQ0JpWlNCeWRXNGdhVzRnUkU5VElHMXZaR1V1RFEwS0pBQUFBQUFBQUFCUVJRQUFUQUVEQVBoa3pvMEFBQUFBQUFBQUFPQUFBZ0VMQVRBQUFHd0JBQUFNQUFBQUFBQUExbjBCQUFB" wide
     

   condition:

      uint16(0) == 0x5a4d and all of them
}

rule redline_payload {
	meta:
	 
	  description = "Rule to detect the RedLine decoded payload"
	  author = "Thatskriptkid"
	  date = "2021-06-17"
	  rule_version = "v1"
	  malware_type = "stealer/backdoor"
	  actor_type = "Cybercrime"
	  actor_group = "Unknown"
	  filetype = "Win 32 EXE .NET"
	  reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"
	  hash = "471A2830FB34FD1BFA68BFC8C3DB3EEE642982ABD4A0BE4E1AC3EBC2A96954CB"
	
	strings:
		// legitimate services for obtaining ip
		$s1 = "https://api.ipify.org" ascii wide
		$s2 = "https://icanhazip.com" ascii wide
		$s3 = "https://wtfismyip.com/text" ascii wide
		$s4 = "https://api.ip.sb/geoip" ascii wide
		$s5 = "https://ipinfo.io/ip" ascii wide
		
		// names of classes with stealer functionality
		$r1 = "OpenVPNRule"
		$r2 = "ProtonVPNRule"
		$r3 = "XMRRule"
		$r4 = "GuardaRule"
		$r5= "AtomicRule"
		$r6 = "DiscordRule"
		$r7 = "EthRule"
		$r8 = "CoinomiRule"
		$r9 = "ElectrumRule"
		$r10 = "DesktopMessangerRule"
		$r11 = "GameLauncherRule"
		$r12 = "FileScannerRule"
		$r13 = "BrowserExtensionsRule"
		$r14 = "AllWalletsRule"
		$r15 = "ExodusRule"
		$r16 = "JaxxRule"
		$r17 = "ArmoryRule"
		
		$xor_algo = {73 [4] 0a 16 0b 2b [1] 06 02 07 6f [4] 03 07 03 6f [4] 5d 6f [4] 61 d1 6f [4] 26 07 17 58 0b 07 02 6f [4] 32 [1] 06 6f [4] 2a}
	condition:
		uint16(0) == 0x5a4d and 
		any of ($s*) and
		$xor_algo and
		any of ($r*)
}