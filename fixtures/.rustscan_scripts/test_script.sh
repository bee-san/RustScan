#!/bin/bash 
#tags = ["core_approved", "example",]
#developer = [ "example", "https://example.org" ]
#ports_separator = ","
#call_format = "bash {{script}} {{ip}} {{port}}"

# The Scriptfile parser stops parsing at the first blank line.
# This script will run itself as an argument with the system installed bash interpreter, scanning all ports concatenated with "," .
# Unused filed: trigger_port = "80"

# print all arguments passed to the script
echo $@
