#!/usr/bin/perl
#
# This script computes messages per minutes and bytes per minutes over
# a time aggregation interval and returns the results normalized to the
# starting time of the trace.
#
# To run this script:
#    snmpseries.pl [<filename>]
#
# (c) 2007 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
#
# $Id: snmpstats.pl 1885 2006-04-18 21:05:55Z schoenw $
# 

use strict;
use POSIX qw(strftime);

my $interval = 60;	# 60 seconds = 1 minute
my $last = 0;
my $bytes = 0;
my $msgs = 0;
my %time_mpm;
my %time_bpm;

my $start = time();

# *********** print functions *************

sub meta_print
{
    printf("# The following table shows some overall meta information in\n" .
	   "# the form of a list of named properties.\n" .
	   "\n");
    printf("%-18s %s\n", "PROPERTY", "VALUE");

    printf("%-18s %s\n", "script-start:",
	   strftime("%FT%T+0000", gmtime($start)));
    printf("%-18s %s\n", "script-end:",
	   strftime("%FT%T+0000", gmtime(time())));
}

sub time_print
{
    printf("\n" .
	   "# The following table show the number of messages / bytes\n" .
	   "# exchanged over time.\n" .
	   "\n");
    printf("%8s %8s %8s\n", "TIME", "MSGS/MIN", "BYTES/MIN");
    foreach my $time (sort {$a <=> $b} (keys %time_mpm)) {
	printf("%8d %8d %8d\n",
	       $time,
	       $time_mpm{$time},
	       $time_bpm{$time});
    }
}


sub process {
    my $file = shift;
    my @series;
    my $t0 = -1;
    if ($file =~ /\.g|Gz|Z$/) {
	open(infile, "zcat $file |") or die "$0: Cannot open $file: $!\n"
    } else {
	open(infile, "<$file") or die "$0: Cannot open $file: $!\n";
    }
    while (<infile>) {
	my @a = split(/,/, $_);
	my $t = $a[0];
	if ($t0 == -1) {
	    $t0 = $t;
	}
	my $x = $t - $t0;
	if ($x >= $last + $interval) {
	    $last = $last + $interval;
	    $time_mpm{$last} = $msgs / $interval;
	    $time_bpm{$last} = $bytes / $interval;
	    $bytes = 0;
	    $msgs = 0;
	}
	$bytes += $a[5];
	$msgs++;
    }
    close(infile);
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
meta_print();
time_print();
exit(0);
