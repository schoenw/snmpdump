#!/usr/bin/perl
#
# This script extracts getbulk parameters from CSV SNMP packet trace 
# files.
#
# To run this script:
#    snmpbulkparm.pl [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
#
# $Id: snmpstats.pl 1974 2006-08-14 21:33:07Z schoenw $
# 

use strict;

sub process {
    my $file = shift;
    my (%non_rep, %max_rep);
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	my @a = split(/,/, $_);
	my $pdu = $a[7];
	if ($pdu =~ "get-bulk-request") {
	    $non_rep{$a[9]}++;
	    $max_rep{$a[10]}++;
	}
    }
    foreach my $num (sort {$a <=> $b} (keys %non_rep)) {
	printf("non-repeater:\t%d\t%d\n", $num, $non_rep{$num});
    }
    foreach my $num (sort {$a <=> $b} (keys %max_rep)) {
	printf("max-repeater:\t%d\t%d\n", $num, $max_rep{$num});
    }
    close(F);
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
