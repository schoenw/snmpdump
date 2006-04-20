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
my %basic_errs;
my %basic_errs_max;
my %basic_nvbs;
my %basic_nvbs_max;

sub basic {
    my $aref = shift;
    my $version = ${$aref}[6];
    my $op = ${$aref}[7];
    my $err = ${$aref}[9];
    if ($err > $basic_errs_max{$op}) {
	$basic_errs_max{$op} = $err;
    }
    my $nvbs = ${$aref}[11];
    if ($nvbs > $basic_nvbs_max{$op}) {
	$basic_nvbs_max{$op} = $nvbs;
    }
    $basic_vers[$version]++;
    $basic_ops{"$version,$op"}++;
    $basic_errs{"$op,$err"}++;
    $basic_nvbs{"$op,$nvbs"}++;
}

sub basic_done {
    my $total = shift;
    printf("# The following table shows the protocol operations statistics\n" .
	   "# broken down by SNMP protocol version plus the overall sums.\n" .
	   "\n");
    printf("%-18s  %12s  %12s  %12s  %12s\n", 
	   "OPERATION", "SNMPv1", "SNMPv2c", "SNMPv3", "TOTAL");
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap2", "inform",
		    "response", "report") {
	printf("%-18s", "$op:");
	foreach my $version (0, 1, 3) {
	    my $val = $basic_ops{"$version,$op"};
	    printf(" %8d %3d\%", $val, $basic_ops{"$version,$op"}*100/$total);
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
    
    printf("\n" .
	   "# The following table shows the distribution of the number of\n" .
	   "# elements in the varbind list broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %15s\n", 
	   "OPERATION", "VARBINDS", "NUMBER");
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap2", "inform",
		    "response", "report") {
	for (my $i = 0; $i <= $basic_nvbs_max{$op}; $i++) {
	    if ($basic_nvbs{"$op,$i"}) {
		printf("%-18s  %12d %12d %3d\%\n", "$op:", $i, 
		       $basic_nvbs{"$op,$i"},
		       $basic_nvbs{"$op,$i"}*100/$total);
	    }
	}
    }

    printf("\n" .
	   "# The following table shows the distribution of the status\n" .
	   "# codes broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %15s\n", 
	   "OPERATION", "STATUS", "NUMBER");
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap2", "inform",
		    "response", "report") {
	for (my $i = 0; $i <= $basic_errs_max{$op}; $i++) {
	    if ($basic_errs{"$op,$i"}) {
		printf("%-18s  %12d %12d %3d\%\n", "$op:", $i, 
		       $basic_errs{"$op,$i"},
		       $basic_errs{"$op,$i"}*100/$total);
	    }
	}
    }
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
