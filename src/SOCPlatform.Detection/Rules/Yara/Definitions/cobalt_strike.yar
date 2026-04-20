rule CobaltStrike_Beacon_Indicators {
  meta:
    description = "Detects strings associated with Cobalt Strike beacon staging / config"
    severity = "critical"
    mitre = "T1055"
  strings:
    $s1 = "beacon.dll" nocase
    $s2 = "beacon_http" nocase
    $s3 = "beacon_https" nocase
    $s4 = "ReflectiveLoader"
    $s5 = "%s.4%08x%s" nocase
    $h1 = { 4d 5a 41 52 55 48 89 }
  condition:
    2 of them
}
