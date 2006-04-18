#!/usr/bin/perl
#
# This script computes basic statistics from CSV SNMP packet trace files.
#
# To run this script:
#    snmpstats.pl [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
#
# $Id$
# 

use strict;

my @basic_vers;
my %basic_ops;

sub basic {
    my $aref = shift;
    my $version = ${$aref}[6];
    my $op = ${$aref}[7];
    $basic_vers[$version]++;
    $basic_ops{"$version,$op"}++;
}

sub basic_done {
    my $total = shift;
    printf("# The following table shows the protocol operations statistics\n" .
	   "# broken down by SNMP protocol version plus the overall sums\n\n");
    printf("%-18s  %12s  %12s  %12s  %12s\n", 
	   "OPERATION", "SNMPv1", "SNMPv2c", "SNMPv3", "TOTAL");
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap2", "inform",
		    "response", "report") {
	printf("%-18s", "$op:");
	foreach my $version (0, 1, 3) {
	    my $val = $basic_ops{"$version,$op"};
	    printf(" %8d %3d\%", $val, 32);
	    $basic_ops{"total,$op"} += $val;
	}
	printf(" %8d %3d\%\n", $basic_ops{"total,$op"}, 
	       $basic_ops{"total,$op"}*100/$total);
    }
    printf("%-18s", "summary:");
    my $sum = 0;
    foreach my $version (0, 1, 3) {
	printf(" %8d %3d\%", $basic_vers[$version],
	       $basic_vers[$version]*100/$total);
	$sum += $basic_vers[$version];
    }
    printf(" %8d %3d\%\n", $sum, $sum*100/$total);
}

sub process {
    my $file = shift;
    my $total = 0;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	my @a = split(/,/, $_);
	basic(\@a);
	$total++;
    }
    basic_done($total);
    close(F);
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
