rule Eva_Aegis_Offensive_Stego_Covert_Channel
{
    meta:
        description = "Detects artifacts from the Eva Aegis offensive engine: steganographic payloads (AEGS magic framing), covert network channel identifiers (DNS/ICMP/TCP timing), XOR key derivation context strings, and anti-forensic function signatures"
        author = "eva-sec-yara-draft"
        date = "2026-10-03"
        severity = "high"
        reference = "src/eva/security_tools/aegis_engine/offensive/"

    strings:
        // Stego payload framing magic bytes (crypto.py L88)
        $magic_aegs = "AEGS" ascii

        // XOR key stream context strings used with Argon2id KDF (crypto.py L177, network_covert.py L177,405)
        $ctx_dns  = "eva-aegis-dns-channel-v1" ascii
        $ctx_icmp = "eva-aegis-icmp-channel-v1" ascii

        // ICMP channel identifier constant 0xAEE5 (network_covert.py L378,492)
        $icmp_ident = { E5 AE }

        // DNS tunnel chunk label prefix pattern: "d" + 4 hex chars (network_covert.py L212)
        $dns_label_re = /d[0-9a-f]{4}[0-9a-f]{20,120}/ ascii nocase

        // Filesystem steganography xattr key (fs_stego.py L3)
        $xattr_key = "user.aegis_payload" ascii

        // Anti-forensic shredder rename pattern marker (shredder.py L51)
        $shred_rename = ".tmp" ascii

        // Timestomp function docstring marker (timestomp.py L9)
        $timestomp_sig = "timestomping" ascii nocase

        // Plausible deniability payload structure markers (crypto.py L111-113)
        $has_decoy_struct = "HasDecoy" ascii nocase

        // Python import of the Aegis offensive crypto module
        $import_aegis_crypto = "aegis_engine.offensive.crypto" ascii

        // Python import of the covert channel module
        $import_covert = "aegis_engine.offensive.channels" ascii

    condition:
        filesize < 50MB and (
            ($magic_aegs at 0) or
            (2 of ($ctx_dns, $ctx_icmp, $import_aegis_crypto, $import_covert, $xattr_key)) or
            ($icmp_ident and $ctx_icmp) or
            ($dns_label_re and ($ctx_dns or $import_covert)) or
            (3 of ($magic_aegs, $ctx_dns, $ctx_icmp, $xattr_key, $shred_rename, $timestomp_sig, $has_decoy_struct, $import_aegis_crypto, $import_covert))
        )
}
