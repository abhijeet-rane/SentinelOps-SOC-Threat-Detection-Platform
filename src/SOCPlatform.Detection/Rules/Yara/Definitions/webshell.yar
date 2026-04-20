rule Generic_WebShell {
  meta:
    description = "Detects signature strings found in common PHP / ASPX web shells"
    severity = "high"
    mitre = "T1505.003"
  strings:
    $php_shell1 = "<?php @eval($_POST["
    $php_shell2 = "c99shell"
    $php_shell3 = "r57shell"
    $aspx_shell1 = "Request.Form[\"cmd\"]"
    $aspx_shell2 = "Process.Start(\"cmd.exe\""
    $china_chop = "@eval(base64_decode(" nocase
  condition:
    any of them
}
