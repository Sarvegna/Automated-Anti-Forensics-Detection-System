rule AntiForensic_SDelete_Signature {
    meta:
        description = "Detects references or signatures associated with Sysinternals SDelete secure file deletion tool"
        author = "Anti-Forensics Detection System"
        severity = "HIGH"
    strings:
        $s1 = "sdelete" nocase
        $s2 = "Secure Delete" nocase
        $s3 = "cleaning free space" nocase
    condition:
        any of ($s1, $s2, $s3)
}

rule AntiForensic_Timestomp_Indicator {
    meta:
        description = "Detects string references associated with timestomping anti-forensic utilities"
        author = "Anti-Forensics Detection System"
        severity = "HIGH"
    strings:
        $t1 = "timestomp" nocase
        $t2 = "setmtime" nocase
        $t3 = "SetFileTime" nocase
    condition:
        any of ($t1, $t2, $t3)
}

rule AntiForensic_LogCleaner_Reference {
    meta:
        description = "Detects references to audit log wiping or clearing utilities"
        author = "Anti-Forensics Detection System"
        severity = "HIGH"
    strings:
        $l1 = "wevtutil cl" nocase
        $l2 = "Clear-EventLog" nocase
        $l3 = "evtcleaner" nocase
    condition:
        any of ($l1, $l2, $l3)
}
