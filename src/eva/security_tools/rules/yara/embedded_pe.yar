rule EmbeddedPEInDocumentOrMedia {
    meta:
        description = "Embedded Windows PE executable inside non-executable file format"
        severity = "critical"
        category = "embedded_executable"
        remediation = "Quarantine carrier file, extract embedded PE executable at offset, and perform full malware analysis."
    strings:
        // MZ header: 4D 5A
        $mz = "MZ"
        // PE signature: 50 45 00 00
        $pe = "PE\x00\x00"
        // DOS stub string
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        // Must NOT start with MZ (i.e. not an ordinary PE file)
        uint16(0) != 0x5A4D
        // Contains MZ, DOS stub and PE signature later in file
        and $mz and $dos_stub and $pe
}

rule EmbeddedPEInPDF {
    meta:
        description = "Embedded Windows PE binary inside PDF document"
        severity = "critical"
        category = "embedded_executable"
        remediation = "Inspect PDF streams for malicious payload droplets or dropper exploits."
    strings:
        $pdf = "%PDF-"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $pdf at 0 and $dos_stub
}

rule EmbeddedPEInImage {
    meta:
        description = "Embedded Windows PE binary inside image container (PNG/JPEG/GIF)"
        severity = "critical"
        category = "embedded_executable"
        remediation = "Isolate image file and check for polyglot or steganographic binary droppers."
    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $jpg = { FF D8 FF }
        $gif = "GIF8"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        ($png at 0 or $jpg at 0 or $gif at 0) and $dos_stub
}
