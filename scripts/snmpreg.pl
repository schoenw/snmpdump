#!/usr/bin/perl -w
#
# This script identifies regular intervals at which packets are sent. It is
# useful to consider logical operations rather than single packets to get an
# overview of regular polling intervals. Hence, it makes sense to use as
# input a CSV SNMP packet trace files containing only packets starting
# interactions (produces with snmpwalks.pl -s).
#

# TODO:

# o add details for OIDs

#
# To run this script:
#    snmpreg.pl [-d] [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id $
# 

use Getopt::Std;
use strict;

my $res = 5; 		# resolution (sampling rate) [s]
#my $tol = 5; 		# allowed jitter [s] # NOT USED !!!
my $min_int = 30; 	# minimum regularity interval to consider
my $max_int = 7200; 	# maximum regularity interval to consider
my %ts; 		# time series data, i.e. time->#packets
my %reg; 		# regularities,i.e. interval_length->#packets
my $packet; 		# complete line representing a packet as seen in input
my $total_packets = 0;  #total number of packets in the input
my $detailed;


#$tol /= $res;
$min_int /= $res;
$max_int /= $res;

sub round {
	my($number) = shift;
	return int($number + .5 * ($number <=> 0));
}

sub min {
	my $a = shift;
	my $b = shift;
	$a = 0 if ! defined $a;
	$b = 0 if ! defined $b;
	if ($a > $b) {
			return $a;
	} else {
			return $b;
	}
}

#
# compare two oids a, b
# returns -1, 0, 1 if a < b, a == b, a > b, respectively
#
sub cmp_oids {
    my $a = shift;
    my $b = shift;
    my @a = split(/\./, $a);
    my @b = split(/\./, $b);
    my $i;
    for ($i = 0; $i < @a && $i < @b;  $i++) {
	if ($a[$i] > $b[$i]) {
	    return 1;
	} elsif ($a[$i] < $b[$i]) {
	    return -1;
	}
    }
    
    if (@a == @b) {
	return 0;
    } elsif (@a > @b) {
	return 1;
    } elsif ($a[$i] < $b[$i]) {
	return -1;
    }
}

#
# load time series data
#
sub load {
    my $aref = shift;
    my $time = ${$aref}[0];
    my $from = ${$aref}[1];
    my $to = ${$aref}[3];
    my $version = ${$aref}[6];
    my $op = ${$aref}[7];	      # snmp operation
    my $request_id = ${$aref}[8];
    my $err_stat = ${$aref}[9];	      # error status
    my $err_ind = ${$aref}[10];	      # error index
    my $varbind_count = ${$aref}[11]; # number of varbinds in this packet

    $total_packets++;
	$time = round($time/$res)*$res;
	$ts{$time}++;
}

#
# try to find events happening at regular intervals in the time series
#
sub reg {
	my @times = sort(keys %ts);
	for(my $i=0; $i<=$#times;$i++) {
		for(my $j=$i+1; $j<=$#times && ($times[$j] - $times[$i]) <= $max_int;$j++) {
			if ($times[$j] - $times[$i] >= $min_int) {
				$reg{$times[$j] - $times[$i]} += min($ts{$times[$i]}, $ts{$times[$j]});
#					for(my $k=-$tol;$k<=$tol;$k++) {
#						$reg{$times[$j] - $times[$i]} += min($ts{$times[$i]}, $ts{$times[$j]+$k});
#					}
			}
		}
	}
}

sub reg_print {
    print "# The following table shows interval lengths (in [s]) and their likelyness.\n";
    print "interval\tlikelyness\n";

#	foreach my $i (sort {$reg{$b} <=> $reg{$a}} (keys %reg)) {
#		last if ($reg{$i} < 2);
	foreach my $i (sort {$a <=> $b} (keys %reg)) {
		printf("%d\t%d\n", $i, $reg{$i}) if $reg{$i} > 2;
	}
}

sub process {
    my $file = shift;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	$packet = $_;
	my @a = split(/,/, $_);
		load(\@a);
    }
	reg();
    reg_print();
	#reg_print_detailed if $detailed_walk_report;
    close(F);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 [-h] [-d] [files|-]
      
This program tries to determine regular intervals in packet arrival times.
	
  -d 			detailed information for OIDS

EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.

my %opt;
getopts( "dh:", \%opt ) or usage();
usage() if defined $opt{h};
$detailed = 1 if defined $opt{d};

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
