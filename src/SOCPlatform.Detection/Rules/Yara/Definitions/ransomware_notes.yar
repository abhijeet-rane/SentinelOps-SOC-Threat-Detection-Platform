rule Ransomware_NoteIndicators {
  meta:
    description = "Detects ransom-note style text fragments"
    severity = "critical"
    mitre = "T1486"
  strings:
    $s1 = "All your files have been encrypted" nocase
    $s2 = "pay the ransom" nocase
    $s3 = "bitcoin address" nocase
    $s4 = "Your network has been compromised" nocase
    $s5 = "decryption tool" nocase
    $s6 = ".onion" nocase
  condition:
    2 of them
}
