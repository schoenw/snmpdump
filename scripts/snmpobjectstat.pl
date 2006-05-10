#!/usr/bin/perl
#
# This script computes from snmpstat.pl generated files the list
# of objects seen in varbind lists. The script only becomes useful
# if MIB information (see -m option) is passed to it.
#
# To run this script:
#    snmpobjectstat.pl [-m MIB_file] [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id$
# 

use Getopt::Std;
use strict;

my %oid_name;		# oid to name mapping
my %oid_count;		# hash (by operation) of hashes (by oid)

#
# load MIB information from file passed as argument
#
sub load_mib {
    my $file = shift;
    open(F, "<$file") or die "Can't open $file: $!";
    while(<F>) {
	my @a = split(/\s+/);
	if ($a[2] =~ /scalar|column|notification/) {
	#if ($a[2] =~ /scalar|column/) {
	    $oid_name{$a[3]} = $a[1];
	}
    }
    close(F);
    print STDERR "loaded ".keys(%oid_name)." oids from file $file\n";
}

sub oid_aggregate {
    # match varbinds to oids
    my %oid_pref_count;
    my %oid_unidentified;
    my $oid_total;
    foreach my $op (keys %oid_count) {
	foreach my $oid (keys %{$oid_count{$op}}) {
	    # match oid to a known oid
	    my $pref = $oid;
	    while(! $oid_name{$pref} && $pref =~ s/(.*)\.\d+$/$1/) {
		# print "oid: $oid, pref: $pref\n";
	    }
	    if ($oid_name{$pref}) {
		# matched $varbind to a known oid
		# print "matched $oid to $pref\n";
		$oid_pref_count{$op}{$pref} += $oid_count{$op}{$oid};
	    } else {
		# print "failed to match $oid\n";
		$oid_unidentified{$op}{$oid} +=
		    $oid_count{$op}{$oid};
	    }
	    $oid_total += $oid_count{$op}{$oid};
	    delete $oid_count{$op}{$oid};
	}
	delete $oid_count{$op};
    }
    my $ident_count;
    foreach my $op (keys %oid_pref_count) {
	$ident_count += keys %{$oid_pref_count{$op}};
    }
    if ($ident_count) {
	printf("\n" .
	       "# The following table shows the identified object oid prefix\n" .
	       "# statistics for each SNMP operation we have seen in the trace.\n" .
	       "\n");
	printf("%-18s %-30s %13s     %s\n", 
	       "OPERATION", "OBJECT", "NUMBER", "NAME");
	foreach my $op (keys %oid_pref_count) {
	    foreach my $oid
		(sort {$oid_pref_count{$op}{$b} <=> $oid_pref_count{$op}{$a}}
		 (keys %{$oid_pref_count{$op}}) )
	    {
		printf("%-18s %-30s %8d %5.1f\% (%s)\n", 
		       $op,
		       $oid, 
		       $oid_pref_count{$op}{$oid},
		       $oid_pref_count{$op}{$oid} / $oid_total * 100,
		       $oid_name{$oid});
	    }
	}
    }

    my $unident_count;
    foreach my $op (keys %oid_unidentified) {
	$unident_count += keys %{$oid_unidentified{$op}};
    }
    if ($unident_count) {
	printf("\n" .
	       "# The following table shows the unidentified object oid\n" .
	       "# statistics for each SNMP operation we have seen in the trace.\n" .
	       "\n");
	printf("%-18s %-50s    %13s\n", 
	       "OPERATION", "UNIDENTIFIED", "NUMBER");
	foreach my $op (keys %oid_unidentified) {
	    foreach my $oid (sort {$oid_unidentified{$op}{$b}
				   <=> $oid_unidentified{$op}{$a}}
			     (keys %{$oid_unidentified{$op}}) ) {
		printf("%-18s %-50s  %10d %5.1f\%\n",
		       $op, $oid, $oid_unidentified{$op}{$oid},
		       $oid_count{$op}{$oid}*100/$oid_total);
	    }
	}
    }
}

sub process {
    my $file = shift;
    my $total = 0;
    my $inoids = 0;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	if (/^OPERATION *OID *NUMBER$/) {
	    $inoids = 1;
	    next;
	} elsif ($inoids) {
	    if (/^$/) {
		last;
	    }
	    my ($op, $oid, $num) = split(/\s+/);
	    $oid_count{$op}{$oid} = $num;
#	    printf("<%s>\t%s\t%d\n", $op, $oid, $num);
#	    $stat{$op}[$size] = $num;
	}
    }
    oid_aggregate($total);
    close(F);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 [-h] [-m mibfile] [files|-]
      
This program computes statistics from SNMP trace files in CSV format.
	
  -h         display this (help) message
  -m mibfile file with MIB information (in smidump -f identifiers format)
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.
my %opt;
getopts( "m:h", \%opt ) or usage();
usage() if defined $opt{h};
load_mib($opt{m}) if defined $opt{m};

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);


