#!/usr/bin/perl
#
# This script tries to find OIDs in input files, lookup them up in a
# mib file and output contents of the input files with known OIDs
# replaces with theior names.  The script only becomes useful if MIB
# information (see -m option) is passed to it. At the end, unknown
# OIDs and some statistics are printed to STDERR. If only a prefix is
# matched, then the OID is repalced by name (matching the prefix)
# appended with the unknown sufffix.
#
# To run this script:
#    snmpoidlookup.pl [-m MIB_file] [<filename.oids>] [> <filename.names>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id$
# 

use Getopt::Std;
use strict;

my %oid_name;		# oid to name mapping
my %unknown_oid;	# unknown oids (count)

my $total = 0;
my $known = 0;
my $unknown = 0;

#
# load MIB information from file passed as argument
#
sub load_mib {
    my $file = shift;
    open(F, "<$file") or die "Can't open $file: $!";
    while(<F>) {
	my @a = split(/\s+/);
	if ($a[2] =~ /scalar|column|notification|node|table|row/) {
	#if ($a[2] =~ /scalar|column|notification/) {
	#if ($a[2] =~ /scalar|column/) {
	    $oid_name{$a[3]} = $a[1];
	}
    }
    close(F);
    print STDERR "loaded ".keys(%oid_name)." oids from file $file\n";
}

sub print_stats {
    print STDERR "\ntotal OIDs seen: $total\n";
    print STDERR "matched OIDs: $known\n";
    print STDERR "unmatched OIDs: $unknown\n";
}

sub print_unknown_oids {
    if (scalar(keys %unknown_oid)) {
	print STDERR "# The following table shows OIDs we were not able ".
		     "to lookup\n\n";
	printf(STDERR "%-60s %10s\n", "OID", "count");
	foreach my $oid ( sort {$unknown_oid{$b} <=> $unknown_oid{$a}}
		       keys %unknown_oid) {
	    printf(STDERR "%-60s %10s\n", $oid, $unknown_oid{$oid});
	}
    }
}

sub oid_lookup {
    my $oid = shift;
    
    $total++;
    # match oid to a known oid
    my $pref = $oid;
    while(! $oid_name{$pref} && $pref =~ s/(.*)\.\d+$/$1/) {
	#print "oid: $oid, pref: $pref\n";
    }
    if ($oid_name{$pref}) {
	# matched $oid to a known oid
	#print "matched $oid to $pref\n";
	$known++;
	return $oid_name{$pref}.substr($oid, length($pref));
    } else {
	#print "failed to match $oid\n";
	$unknown++;
	return "";
    }
    return "";
}

sub process {
    my $file = shift;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	my $line = $_;
	my @words = split;
	foreach my $word (@words) {
	    if ($word =~ /^\d(\.\d+)+$/) {
		my $oid = $word;
		my $name = oid_lookup($oid);
		if ($name) {
		    # probably we shjould count \d+ to make sure we
		    # are replacing the right part of the line
		    #print STDERR "replacing $oid with $name\n";
		    $line =~ s/$oid/$name/;
		} else {
		    #print STDERR "no match for $oid\n";
		    $unknown_oid{$oid}++;
		}
	    }
	}
	print $line;
	    
    }
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
print_unknown_oids();
print_stats();
exit(0);
