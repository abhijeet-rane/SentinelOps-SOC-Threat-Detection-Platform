rule Mimikatz_Strings {
  meta:
    description = "Detects characteristic Mimikatz strings in payloads or command lines"
    severity = "critical"
    mitre = "T1003.001"
  strings:
    $s1 = "sekurlsa::logonpasswords" nocase
    $s2 = "sekurlsa::pth" nocase
    $s3 = "lsadump::sam" nocase
    $s4 = "gentilkiwi" nocase
    $s5 = "mimikatz" nocase
  condition:
    any of them
}
