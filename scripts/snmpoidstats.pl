#!/usr/bin/perl
#
# This script computes which OIDs have been used and how frequently. 
# Usually, the output is processed by another script that further
# aggregates data based on MIB module information.
#
# To run this script:
#    snmpoidstats.pl [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id: snmpstats.pl 1974 2006-08-14 21:33:07Z schoenw $
# 

use Getopt::Std;
use strict;

my %oid_count;		# hash (by operation) of hashes (by oid)
my %oid_unidentified;	# varbinds for which we have not found a matching oid
			# hash (by operation) of hashes (by varbinds) 
my $oid_total;		# how many varbinds have we seen

#
# Count varbinds for each operation.
#
sub oid {
    my $aref = shift;
    my $op = ${$aref}[7];	      # snmp operation
    my $varbind_count = ${$aref}[11]; # number of varbinds in this packet
    for (my $i = 0; $i < $varbind_count; $i++) {
	my $oid =  ${$aref}[12 + 3*$i];
	$oid_count{$op}{$oid}++;
    }
    $oid_total += $varbind_count;
}

#
# Print the data we have accumulated in the global hashes.
#
sub results {
    printf("\n" .
	   "# The following table shows the oid statistics for each\n".
           "# SNMP operation we have seen in the trace.\n" .
	   "\n");
    printf("%-18s %13s    %s\n", 
	   "OPERATION", "NUMBER", "OID");
    foreach my $op (keys %oid_count) {
	foreach my $oid (sort {$oid_count{$op}{$b}
			       <=> $oid_count{$op}{$a}}
			 (keys %{$oid_count{$op}}) ) {
	    printf("%-18s %8d %5.1f%%  %s\n",
		   $op, 
		   $oid_count{$op}{$oid},
		   $oid_count{$op}{$oid}*100/$oid_total,
		   $oid);
	}
    }
}

#
# Process a single input file.
#
sub process {
    my $file = shift;
    if ($file =~ /\.g|Gz|Z$/) {
	open(infile, "zcat $file |") or die "$0: Cannot open $file: $!\n"
    } else {
	open(infile, "<$file") or die "$0: Cannot open $file: $!\n";
    }
    while (<infile>) {
	my @a = split(/,/, $_);
	oid(\@a);
    }
    close(infile);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 [-h] [files|-]
      
This program computes statistics from SNMP trace files in CSV format.
	
  -h         display this (help) message
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the command-line in turn
# and finally print the statistics aggregated over all input files.

my %opt;
getopts( "h", \%opt ) or usage();
usage() if defined $opt{h};

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
results();
exit(0);
