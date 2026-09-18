rule ObfuscatedPowerShellInvocation {
    meta:
        description = "Obfuscated PowerShell execution flags and encoded command arguments"
        severity = "high"
        category = "obfuscation"
        remediation = "Investigate calling process parentage, decode encoded payload, and review event log 4688 / 4104."
    strings:
        $enc1 = "-enc" nocase wide ascii
        $enc2 = "-encodedcommand" nocase wide ascii
        $hidden = "-w hidden" nocase wide ascii
        $nop = "-nop" nocase wide ascii
        $bypass = "-ep bypass" nocase wide ascii
        $cradle1 = "DownloadString" nocase wide ascii
        $cradle2 = "DownloadFile" nocase wide ascii
        $iex1 = "Invoke-Expression" nocase wide ascii
        $iex2 = "IEX" nocase wide ascii
    condition:
        filesize < 5MB and (
            ($enc1 or $enc2) or
            (($hidden or $nop or $bypass) and ($cradle1 or $cradle2 or $iex1 or $iex2))
        )
}

rule Base64EncodedPE {
    meta:
        description = "Base64 encoded Windows PE executable binary (MZ header prefix)"
        severity = "high"
        category = "payload"
        remediation = "Decode base64 buffer and analyze decoded PE binary."
    strings:
        // 'TVqQ' is base64 for 'MZ\x90'
        $b64_pe1 = "TVqQAAMAAAAEAAAA" ascii wide
        $b64_pe2 = "TVpQAAIAAAAAEAAA" ascii wide
    condition:
        filesize < 50MB and any of ($b64_pe*)
}
