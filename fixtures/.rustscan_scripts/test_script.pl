#!/usr/bin/perl
#tags = ["core_approved", "example",]
#developer = [ "example", "https://example.org" ]
#ports_separator = ","
#call_format = "perl {{script}} {{ip}} {{port}}"

# The Scriptfile parser stops parsing at the first blank line.
# This script will run itself as an argument with the system installed perl interpreter, ports will be concatenated with "," .
# Unused field: trigger_port = "80"
# get total arg passed to this script
my $total = $#ARGV + 1;
my $counter = 1;
 
# get script name
my $scriptname = $0;
 
print "Total args passed to $scriptname : $total\n";
 
# Use loop to print all args stored in an array called @ARGV
foreach my $a(@ARGV) {
	print "Arg # $counter : $a\n";
	$counter++;
}
