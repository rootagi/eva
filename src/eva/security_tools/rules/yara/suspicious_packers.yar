rule SuspiciousPackerUPX {
    meta:
        description = "UPX executable packer signature"
        severity = "medium"
        category = "packer"
        remediation = "Analyze binary with memory dump unpacking to inspect underlying executable code."
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"
        $upx_sig = "UPX!"
    condition:
        uint16(0) == 0x5A4D and ($upx_sig or all of ($upx0, $upx1) or any of ($upx*))
}

rule SuspiciousPackerASPack {
    meta:
        description = "ASPack executable packer signature"
        severity = "medium"
        category = "packer"
        remediation = "Unpack binary or inspect process memory to analyze payload."
    strings:
        $aspack1 = ".aspack" nocase
        $aspack2 = "ASPack compressor" nocase
    condition:
        uint16(0) == 0x5A4D and any of ($aspack*)
}

rule SuspiciousPackerThemida {
    meta:
        description = "Themida / WinLicense protector markers"
        severity = "high"
        category = "packer"
        remediation = "Examine binary in dynamic sandbox environment due to strong anti-analysis armor."
    strings:
        $themida1 = ".themida" nocase
        $themida2 = "Themida" ascii wide
        $themida3 = "WinLicense" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of ($themida*)
}

rule SuspiciousPackerPECompact {
    meta:
        description = "PECompact packed executable"
        severity = "medium"
        category = "packer"
        remediation = "Unpack executable before performing static disassembly."
    strings:
        $pec1 = "PECompact2" nocase
        $pec2 = "PEC2"
    condition:
        uint16(0) == 0x5A4D and any of ($pec*)
}
