rule PowerShell_Obfuscation {
  meta:
    description = "Detects heavy PowerShell obfuscation constructs (FromBase64String, IEX, encoded cradle)"
    severity = "high"
    mitre = "T1059.001"
  strings:
    $s1 = "FromBase64String" nocase
    $s2 = "Invoke-Expression" nocase
    $s3 = "IEX(" nocase
    $s4 = "DownloadString" nocase
    $s5 = "New-Object Net.WebClient" nocase
    $r1 = /-[eE][nN][cC](odedCommand)?/
  condition:
    any of ($s*) or $r1
}
