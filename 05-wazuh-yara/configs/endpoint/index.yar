// File:    /opt/yara/rules/index.yar
// Machine: ubuntu-endpoint
// Purpose: the one file Wazuh passes to YARA. It loads all rule files.
include "/opt/yara/rules/valhalla_rules.yar"
include "/opt/yara/rules/lab_rules.yar"
