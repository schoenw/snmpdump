#!/usr/bin/perl
#
# This script computes from CSV SNMP packet trace files:
#
# o basic statistics
# o counts oids for each SNMP operaiton
#
# To run this script:
#    snmpstats.pl [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id$
# 

use Getopt::Std;
use strict;

my @snmp_ops = ("get-request", "get-next-request", "get-bulk-request",
		"set-request", 
		"trap", "trap2", "inform", 
		"response", "report", "");

my $meta_first = 0;
my $meta_last = 0;
my %meta_agents;
my %meta_managers;
my %meta_unknowns;

my @basic_vers;
my %basic_ops;
my %basic_errs;
my %basic_errs_max;
my %basic_nvbs;
my %basic_nvbs_max;
my %basic_size;

my %oid_count;		# hash (by operation) of hashes (by oid)
my %oid_unidentified;	# varbinds for which we have not found a matching oid
			# hash (by operation) of hashes (by varbinds) 
my $oid_total;		# how many varbinds have we seen

sub meta {
    my $aref = shift;
    my $secs = ${$aref}[0];
    my $src = ${$aref}[1];
    my $dst = ${$aref}[3];
    my $op = ${$aref}[7];

    if ($secs > 0) {
	$meta_last = $secs;
	if ($meta_first == 0) {
	    $meta_first = $meta_last;
	}
    }

    for ($op) {
        if (/get-request|get-next-request|get-bulk-request|set-request/) {
            $meta_managers{$src}++;
            $meta_agents{$dst}++;
        } elsif (/trap|trap2|inform/) {
            $meta_managers{$dst}++;
            $meta_agents{$src}++;
	} elsif (/response|report/) {
	    $meta_unknowns{$dst}++;
            $meta_unknowns{$src}++;
	} else {
	    printf("oouch\n");
        }
    }

}

sub meta_print {
    my $total = shift;
    my $gmt;
    my $duration = $meta_last - $meta_first;
    printf("# The following table shows some overall meta information in\n" .
	   "# the form of a list of named properties.\n" .
	   "\n");
    printf("%-18s %s\n", "PROPERTY", "VALUE");
#    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($meta_first);
    $gmt = gmtime($meta_first);
    printf("%-18s %s\n", "start:", $gmt);
    $gmt = gmtime($meta_last);
    printf("%-18s %s\n", "end:", $gmt);
    printf("%-18s %s\n", "days:", $duration/60/60/24);
    printf("%-18s %s\n", "hours:", $duration/60/60);
    printf("%-18s %s\n", "minutes:", $duration/60);
    printf("%-18s %s\n", "messages:", $total);

    foreach my $addr (keys %meta_unknowns) {
	if (exists $meta_managers{$addr} || exists $meta_agents{$addr}) {
	    delete $meta_unknowns{$addr};
	}
    }

    printf("%-18s %s\n", "managers:", scalar keys(%meta_managers));
    printf("%-18s %s\n", "agents:", scalar keys(%meta_agents));
    printf("%-18s %s\n", "unknown:", scalar keys(%meta_unknowns));
}

sub basic {
    my $aref = shift;
    my $size = ${$aref}[5];
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
    $basic_size{$op}{$size}++;
}

sub basic_print {
    my $total = shift;
    printf("\n" .
	   "# The following table shows the protocol operations statistics\n" .
	   "# broken down by SNMP protocol version plus the overall sums.\n" .
	   "\n");
    printf("%-18s  %14s  %14s  %14s  %14s\n", 
	   "OPERATION", "SNMPv1", "SNMPv2c", "SNMPv3", "TOTAL");
    foreach my $op (@snmp_ops) {
	printf("%-18s", "$op:");
	foreach my $version (0, 1, 3) {
	    my $val = $basic_ops{"$version,$op"};
	    printf(" %8d %5.1f%%", $val, $basic_ops{"$version,$op"}*100/$total);
	    $basic_ops{"total,$op"} += $val;
	}
	printf(" %8d %5.1f\%\n", $basic_ops{"total,$op"}, 
	       $basic_ops{"total,$op"}*100/$total);
    }
    printf("%-18s", "summary:");
    my $sum = 0;
    foreach my $version (0, 1, 3) {
	printf(" %8d %5.1f\%", $basic_vers[$version],
	       $basic_vers[$version]*100/$total);
	$sum += $basic_vers[$version];
    }
    printf(" %8d %5.1f\%\n", $sum, $sum*100/$total);
    
    printf("\n" .
	   "# The following table shows the distribution of the number of\n" .
	   "# elements in the varbind list broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %16s\n", 
	   "OPERATION", "VARBINDS", "NUMBER");
    foreach my $op (@snmp_ops) {
	for (my $i = 0; $i <= $basic_nvbs_max{$op}; $i++) {
	    if ($basic_nvbs{"$op,$i"}) {
		printf("%-18s  %12d %12d %5.1f%%\n", "$op:", $i, 
		       $basic_nvbs{"$op,$i"},
		       $basic_nvbs{"$op,$i"}*100/$total);
	    }
	}
    }

    printf("\n" .
	   "# The following table shows the distribution of the status\n" .
	   "# codes broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %16s\n", 
	   "OPERATION", "STATUS", "NUMBER");
    foreach my $op (@snmp_ops) {
	for (my $i = 0; $i <= $basic_errs_max{$op}; $i++) {
	    if ($basic_errs{"$op,$i"}) {
		printf("%-18s  %12d %12d %5.1f%%\n", "$op:", $i, 
		       $basic_errs{"$op,$i"},
		       $basic_errs{"$op,$i"}*100/$total);
	    }
	}
    }

    printf("\n" .
	   "# The following table shows the message size distribution\n" .
	   "# broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %8s  %15s\n",
	   "OPERATION", "SIZE", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $size (sort {$a <=> $b}
			  (keys %{$basic_size{$op}})) {
	    printf("%-18s  %8d  %10d %5.1f%%\n",
		   "$op:", $size, $basic_size{$op}{$size},
		   $basic_size{$op}{$size}*100/$total);
	}
    }
}

#
# count varbinds for each operation
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

sub oid_print {
    my $total = shift;
    # dump unknown oids
    printf("\n" .
	   "# The following table shows the oid statistics for each\n".
           "# SNMP operation we have seen in the trace.\n" .
	   "\n");
    printf("%-18s %-50s    %13s\n", 
	   "OPERATION", "OID", "NUMBER");
    foreach my $op (keys %oid_count) {
	foreach my $oid (sort {$oid_count{$op}{$b}
			       <=> $oid_count{$op}{$a}}
			 (keys %{$oid_count{$op}}) ) {
	    printf("%-18s %-40s  %10d %5.1f%%\n",
		   $op, $oid, $oid_count{$op}{$oid},
		   $oid_count{$op}{$oid}*100/$oid_total);
	}
    }
}

sub process {
    my $file = shift;
    my $total = 0;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	my @a = split(/,/, $_);
	meta(\@a);
	basic(\@a);
	oid(\@a);
	$total++;
    }
    meta_print($total);
    basic_print($total);
    oid_print($total);
    close(F);
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
# arguments and then process all files on the commandline in turn.

my %opt;
getopts( "h", \%opt ) or usage();
usage() if defined $opt{h};

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
