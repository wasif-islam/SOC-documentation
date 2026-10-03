/*
  File:    /opt/yara/rules/lab_rules.yar
  Machine: ubuntu-endpoint
  Purpose: one harmless rule that proves YARA and the Wazuh integration work.
           Every YARA rule has the same three parts: meta, strings, condition.
*/
rule LAB_Test_Marker
{
    meta:
        description = "Harmless test file for the YARA lab"
        author      = "soc-documentation"

    strings:
        $text = "YARA-LAB-TEST-MARKER" ascii   // a specific text string
        $hex  = { 4C 41 42 2D 30 35 }           // a byte pattern (these bytes spell LAB-05)

    condition:
        $text and $hex and filesize < 1KB       // both patterns AND a file property
}
