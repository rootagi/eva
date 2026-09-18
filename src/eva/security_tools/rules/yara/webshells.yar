rule PhpWebshellGeneric {
    meta:
        description = "Generic PHP webshell code execution signatures"
        severity = "high"
        category = "webshell"
        remediation = "Quarantine file, review web server access logs for unauthorized file upload, and remove backdoors."
    strings:
        $p1 = "eval(base64_decode(" nocase
        $p2 = "eval(gzinflate(" nocase
        $p3 = "eval(gzuncompress(" nocase
        $p4 = "passthru($_" nocase
        $p5 = "shell_exec($_" nocase
        $p6 = "system($_" nocase
        $p7 = "assert($_POST" nocase
        $p8 = "preg_replace(\"/.*/e\"" nocase
    condition:
        filesize < 20MB and (any of ($p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8))
}

rule JspWebshellRuntimeExec {
    meta:
        description = "JSP webshell invoking Runtime.getRuntime().exec or ProcessBuilder"
        severity = "high"
        category = "webshell"
        remediation = "Isolate application container, remove untrusted JSP files, and inspect reverse proxy logs."
    strings:
        $jsp1 = "<%@ page" nocase
        $exec1 = "Runtime.getRuntime().exec("
        $exec2 = "ProcessBuilder("
        $req1 = "request.getParameter("
    condition:
        filesize < 5MB and ($jsp1 or $req1) and ($exec1 or $exec2)
}

rule AspxWebshellCommand {
    meta:
        description = "ASPX/ASP webshell executing system commands or process start"
        severity = "high"
        category = "webshell"
        remediation = "Quarantine file and review IIS application pool logs and upload directories."
    strings:
        $aspx1 = "<%@ Page Language=" nocase
        $cmd1 = "ProcessStartInfo" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "powershell.exe" nocase
        $wscript = "WScript.Shell" nocase
    condition:
        filesize < 5MB and (($aspx1 and any of ($cmd1, $cmd2, $cmd3)) or $wscript)
}

rule ChinaChopperWebshell {
    meta:
        description = "China Chopper single-line webshell signature"
        severity = "critical"
        category = "webshell"
        remediation = "Remove China Chopper webshell immediately and rotate credentials."
    strings:
        $cc_php = /<\?php\s+@?(eval|assert)\(\$_POST\[[^\]]+\]\);\s*\?>/ nocase
        $cc_aspx = /<%@\s*Page\s+Language="Jscript"\s*%>.*eval\(RequestItem\[/ nocase
    condition:
        filesize < 100KB and ($cc_php or $cc_aspx)
}
