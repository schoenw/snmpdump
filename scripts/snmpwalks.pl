#!/usr/bin/perl -w
#
# This script tries to extract talbe walks out of CSV SNMP packet
# trace files. Optionally, detected walks are written into separate
# files in specified directory.
#

# A walk is defined as a series of get-next/response or
# get-bulk/response operations. A mixture of get-next and get-bulk
# requests is not considered a walk. Oids in the requests in the same
# varbind index (corresponding to the same table column) are
# increasing lexicographically and have the same oid prefix. This
# prefix is obtained from the first request within the walk. A request
# may have oid lexicographically lower than the one in previous
# response in case of table holes. A walk is ended if the
# lexicographical order is broken, i.e. the agent wraps back to the
# beginning of the table or the response contains a different oid
# prefix than the (initial) request for all varbinds (some columns may
# be shorter than others, but the walks ends when we reach the end of
# the longest column rather than the shortest one).

# WORKAROUNDS:

# net-snmp snmptable starts a bulk walk appending .0 to the table oid
# when using protocol version 2c. In order to detect walks properly,
# we strip off the trailing .0 and print a warning.

# BUGS:

# [P/A/Opaque] timestamps screw up duration calculations.

# Timeout not tested much.

# If we miss the first walk request, we probably miss also the oid
# prefix. We could figure out the prefix also later on during the walk
# by checking MIB information, but we're not doing it at the moment.

# We do not distinguish two concurrent walks for the same OID prefix.

# The above definition of a walk may miss some non-standard walks. It
# is questionabble whether these really should be considered walks.

# If columns are of different length and the agent would wrap back to
# the beginning of the table, we would probably notnotice the end of
# the walk.

# Receiving duplicated requests would probably screw up statistics.

# TODO:

# o sort table 1 by repetitions
# o cleanup code
# o don't dump walks with 1 interaction only

#
# To run this script:
#    snmpwalks.pl [-d directory] [-W] [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id$
# 

use Getopt::Std;
use File::Basename;
use strict;

my @snmp_ops = ("get-request", "get-next-request", "get-bulk-request",
		"set-request", 
		"trap", "trap2", "inform", 
		"response", "report", "");

# my %oid_name;		# oid to name mapping
# my %varbind_count;	# hash (by operation) of hashes (by varbinds)
# my %oid_count;	# hash (by operation) of hashes (by oids)
# my %oid_unidentified;	# varbinds for which we have not found a matching oid
# 			# hash (by operation) of hashes (by varbinds) 
# my @oid_op_total;	# how many varbinds have we seen for each operation
# 			# (includes also unidentified varbinds)

my @walks_open;		# open walks, array of hashes
my @walks_closed;	# closed walks
my @walks_degen;	# degenerated walks (1 iterations only)
			# NOTE: only @walks_closed are considered
my @walks_timeout;	# walks timed out
			# NOT TESTED THOUROUGHLY
# the walk hash contaisn the following elements:
# o manag_ip	 - command generator (manager) IP address
# o agent_ip	 - command responder (agent) IP address
# o start_time	 - time we have seen the first packet in the walk
# o end_time	 - time we have seen the last packet in the walk
# o vb_count     - total number of varbinds in the whole walk
#		   (sum of all packets)
# o op		 - SNMP operation starting the walk (request)
# o request_id   - request-id (from last request packet)
# o @pref	 - OID prefixes (OIDs from the first request packet)
#		   NOTE: net-snmp snmtable gets special treatment
# o @last_oid	 - last requested OIDs  (from the last request packet)
# o non-rep	 - non-repeaters
# o rep		 - repeaters
#		   for get-next walks rep and non-rep are determined
#		   from the second request packet
# o max-rep	 - max-repetitions
# o repetitions  - #repetitions added up for the whole walk
#		   ignores last repetitition of incomplete
#		   NOTE: for a single get-next repsonse always one
#			 (hence it will be number of repsonses)
# o resp_vbs	 - varbinds in responses summed up for the whole walk
# o packets	 - number of packets in the walk
# o interactions - number of interations (request response pairs) in the walk,
#		   i.e. counting requests
# o F		 - file handle for output
# o name	 - unique name of the (input_file."-".walk_number)

my %pref_count;		# OID prefixes starting a walk
my %prefs_count;	# OID prefixes starting a walk grouped by walks
			# both are arrays of hashes with following elements:
			# o count
			# o repetitions
my $walks_total = 0;    # number of walks seen
my $walks_total_packets # number of packets belonging to walks
    = 0;
my $total_packets = 0;  # total number of packets seen


my $file;	        # currently processed input file
my $packet;	        # string representing the original packet as read
		        # from the input CSV file
# cmd-line switches
my $dirout;	        # directory where the walk files should go
		        # no files written if not set
my $timeout;		# timeout in s for closing an open walk
my $detailed_walk_report# produce a detailed report for each walk?
    = 0;

# We need the following information to identify a walk:
# o manager IP
# o agent IP
# o number of varbinds
# o OID prefix (array)
# o last requested OID (array)
# o last request ID
# o ? SNMP version

# additionally we keep the following information about a walk:
# o number of packets
# o number of interactions (request-response pairs, i.e. counting requests)
# o xxx number of holes seen
# o file handle for output
# o walk ID

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
# try to detect table walks
#
sub walk {
    my $aref = shift;
    my $from = ${$aref}[1];
    my $to = ${$aref}[3];
    my $version = ${$aref}[6];
    my $op = ${$aref}[7];	      # snmp operation
    my $request_id = ${$aref}[8];
    my $err_stat = ${$aref}[9];	      # error status
    my $err_ind = ${$aref}[10];	      # error index
    my $varbind_count = ${$aref}[11]; # number of varbinds in this packet
    my $manag_ip;
    my $agent_ip;
    my $found = 0;
    #my %walk;
    my $walk;	# reference

    $total_packets++;
    if ($op =~ /get-next-request|get-bulk-request/) {
	$manag_ip = $from;
	$agent_ip = $to;
	WALKS: foreach my $w ( @walks_open ) {
	    if ($w->{"manag_ip"} eq $manag_ip
		&& $w->{"agent_ip"} eq $agent_ip
		&& $w->{"op"} eq $op
		&& $w->{"vbc"} == $varbind_count) {
		# do OIDs match the prefix?
		# are OIDs lex. >= than in previous request ?
		#print "checking oids...\n";
		for (my $i = 0; $i < $varbind_count; $i++) {
		    my $oid =  ${$aref}[12 + 3*$i];
		    my $last_oid =  $w->{"last_oid"}[$i];
		    my $pref = $w->{"pref"}[$i];
		    if ($oid =~ /^$pref/
			&& cmp_oids($oid, $last_oid) > 0 ) {
			$found = 1;
			$walk = $w;
			#print "found walk: $walk->{'manag_ip'}\n";
			last WALKS;
		    }
		}
	    }
	}
	if ($found) {
	    # existing walk
#	    print "found walk: $walk->{'manag_ip'}\n";
# 	    print "packet oids: ";
# 	    print "@{$walk->{'last_oid'}}";
# 	    print "\n matched to walk with oid prefixes: ";
# 	    print "@{$walk->{'pref'}}";
# 	    print "\n";
	    
	    # determine rep and non-rep for a get-next walk
	    # use only the second packet
	    if ($walk->{'op'} eq "get-next-request"
		&& $walk->{'interactions'} == 1) {
		$walk->{"rep"} = 0;
		$walk->{"non-rep"} = 0;
		for (my $i = 0; $i < $varbind_count; $i++) {
		    my $oid =  ${$aref}[12 + 3*$i];
		    my $pref = $walk->{"pref"}[$i];
		    
		    my $cmp = cmp_oids($oid, $pref);
		    if ($cmp > 0) {
			$walk->{"rep"}++;
		    } elsif ($cmp == 0) {
			$walk->{"non-rep"}++;
		    }else {
			    print STDERR "WARNING repsonse OID in a walk ".
				"is < OID in initial request\n";
			}
		}
	    }
	} else {
	    # first packet of a walk - starts a new walk
	    $walks_total++;
	    $walk = {}; # create a new walk and give us the reference to it
	    push(@walks_open, $walk);
	    if (defined $dirout) {
		my $filename = $dirout."/".basename($file)."-$walks_total";
		open(my $f, ">$filename")
		    or die "$0: unable to open $filename: $!\n";
		$walk->{"F"} = \*$f;
	    }
	    $walk->{'name'} = basename($file)."-$walks_total";
	    $walk->{'start_time'} = ${$aref}[0];
	    $walk->{"manag_ip"} = $manag_ip;
	    $walk->{"agent_ip"} = $agent_ip;
	    $walk->{"op"} = $op;
	    $walk->{"vbc"} = $varbind_count;
	    # save OID prefix for this walk
	    for (my $i = 0; $i < $varbind_count; $i++) {
		my $oid =  ${$aref}[12 + 3*$i];
		# check for non-standard net-snmp snmptable get-bulk
		if ($oid =~ /\.0$/) {
		    print STDERR
			"WARNING: oid prefix ending with .0 starting a walk\n".
			"\tprobably net-snmp snmptable, ".
			"stripping off the .0\n";
		    $oid =~ s/(\.0$)//;
		}
		$walk->{"pref"}[$i] = $oid;
	    }
	    #print "packet starting a new walk, oids: ";
	    #print "@{$walk->{'pref'}}";
	    #print "\n";   
	}
	# common code for both new and existing walks
	for (my $i = 0; $i < $varbind_count; $i++) {
	    my $oid =  ${$aref}[12 + 3*$i];
	    $walk->{"last_oid"}[$i] = $oid;
	}
	$walk->{'request_id'} = $request_id;
	$walk->{'packets'}++;
	$walk->{'interactions'}++;
	#$walk->{"op"} = $op;
	$walk->{'end_time'} = ${$aref}[0];
	print {$walk->{"F"}} $packet if defined $dirout;
	if ($walk->{'op'} eq "get-bulk-request") {
	    $walk->{'non-rep'} = $err_stat;
	    $walk->{'max-rep'} = $err_ind;
	    $walk->{'rep'} = $varbind_count - $walk->{'non-rep'};
	}
	$walks_total_packets++;
    }
    if ($op =~ /response/) {
	# match to request (probably last active walk)
	$manag_ip = $to;
	$agent_ip = $from;
	my $prefix_match = 0;
	foreach my $w ( @walks_open ) {
	    if ($w->{"manag_ip"} eq $manag_ip
		&& $w->{"agent_ip"} eq $agent_ip
		# varbind_count would not match for get-bulk response
		# && $w->{"varbind_count"} == $varbind_count
		&& $w->{"request_id"} == $request_id) {
		# split based on response to get-next or get-bulk
		if ($w->{"op"} eq "get-next-request") {
		    # are OIDs lex. >= than in previous request ?
		    for (my $i = 0; $i < $varbind_count; $i++) {
			my $oid =  ${$aref}[12 + 3*$i];
			my $last_oid =  $w->{"last_oid"}[$i];
			my $pref = $w->{"pref"}[$i];
			if (cmp_oids($oid, $last_oid) > 0 ) {
			    $found = 1;
			    last;
			}
		    }
		} elsif ($w->{"op"} eq "get-bulk-request") {
		    # are OIDs lex. >= than in previous request ?
		    # sufficient to check only the first repetitions
		    # ? optimization: ignore non-repeaters
		    for (my $i = 0; $i < $w->{"vbc"}; $i++) {
			my $oid =  ${$aref}[12 + 3*$i];
			my $last_oid =  $w->{"last_oid"}[$i];
			my $pref = $w->{"pref"}[$i];
			if (cmp_oids($oid, $last_oid) > 0 ) {
			    $found = 1;
			    last;
			}
		    }
		}
	    }
	    if ($found) {
		$walk = $w;
		#print "found walk: $walk->{'manag_ip'}\n";
		last;
	    }
	}
	if ($found) {
	    # found a walk for this response
	    $walk->{"packets"}++;
	    $walks_total_packets++;
 	    print {$walk->{"F"}} $packet if defined $dirout;
	    $walk->{"resp_vbs"} += $varbind_count;
	    $walk->{'end_time'} = ${$aref}[0];
	    # split based on response to get-next or get-bulk
	    if ($walk->{"op"} eq "get-next-request") {
		# does at least one OID match the prefix?
		for (my $i = 0; $i < $varbind_count; $i++) {
		    my $oid =  ${$aref}[12 + 3*$i];
		    my $pref = $walk->{"pref"}[$i];
		    if ($oid =~ /^$pref/) {
			$prefix_match = 1;
			last;
		    }
		}
		# repetitions for get-next are always one
		$walk->{"repetitions"}++;
	    } elsif ($walk->{"op"} eq "get-bulk-request") {
		# determine number of repetitions
		my $reps = ($varbind_count - $walk->{'non-rep'})
		    / $walk->{'rep'};
		$walk->{"repetitions"} += $reps;
		my $repeaters = $walk->{"vbc"} - $walk->{'non-rep'};
		# ignore non-repeateres
		# ignore last repetition if incomplete
		# does at least one OID in each repetition match the prefix?
		for (my $rep = 0; $rep < $reps; $rep++) {
		    $prefix_match = 0;
		    for (my $i = 0; $i < $repeaters; $i++) {
			my $j = $walk->{'non-rep'} + $rep*$repeaters + $i;
 			my $oid =  ${$aref}[12 + 3*$j];
			my $pref = $walk->{"pref"}[$i];
			if ($oid =~ /^$pref/) {
			    $prefix_match = 1;
			    last;
			}
		    }
		    if (! $prefix_match) {
			# no OID matches prefix
			last;
		    }
		}
	    }
	    if (! $prefix_match) {
		# all OIDs have run out of prefix, hence this walk is ended
		#print "walk ended - out of prefix (${$aref}[12])\n";
		#$walks_closed_ok++;
		#walk_print_single($walk);
		for (my $i=0; $i<= $#walks_open;) {
		    if ($walks_open[$i] ==  $walk) {
			push(@walks_closed, $walk);
			#delete $walks_open[$i];
			splice @walks_open, $i, 1;
			last;
		    } else {
			$i++;
		    }
		}
	    }
	} else {
	    # response does not belong to an open walk
	}
	# timeout
	if (defined $timeout) {
	    for (my $i=0; $i<= $#walks_open;) {
		my $w = $walks_open[$i];
		if (${$aref}[0] + $timeout > $w->{'end_time'}) {
		    push(@walks_timeout, $walk);
		    splice @walks_open, $i, 1;
		} else {
		    $i++;
		}
	    }
	}
	# optional: try to detect holes
    }
}

sub walk_print_single {
    my $walk = shift;
    #my %walk = %{$aref};
    print "name: $walk->{'name'}\n";
    print "number of packets: $walk->{'packets'}\n";
    print "number of interactions: $walk->{'interactions'}\n";
    print "number of columns retreived in parallel: ".@{$walk->{'pref'}}."\n";
    print "non-repeaters: $walk->{'non-rep'}\n";
    print "repeaters: $walk->{'rep'}\n";
    print "repetitions: $walk->{'repetitions'}\n";
    print "response_verbinds: $walk->{'resp_vbs'}\n";
    print "operation: $walk->{'op'}\n";
    print "start time: $walk->{'start_time'}\n";
    print "end time: $walk->{'end_time'}\n";
    print "duration: ";
    if (defined $walk->{'end_time'}) {
	print $walk->{'end_time'} - $walk->{'start_time'};
    }
    print "\n";
    print "oid prefixes starting the walk: @{$walk->{'pref'}}\n";
    if ($walk->{'packets'} != 2*$walk->{'interactions'}) {
	print "WARNING: number of packets is not twice number ".
	      "of interactions, ".
	      "probably not all packets have been captured!\n";
    }
    print "\n";
}

#
# filter degenerated walks (one iteration only) from walks_closed
#
sub filter_degenerated_walks {
    for (my $i = 0; $i <= $#walks_closed; ) {
	if ($walks_closed[$i]->{'interactions'} <= 1) {
	    push(@walks_degen, $walks_closed[$i]);
	    #delete $walks_closed[$i]; # this does not work as expected !!!
	    splice @walks_closed, $i, 1;
	} else {
	    $i++;
	}
    }
}

sub walk_print_detailed {
    print "# The following shows detailed information about properly " .
	  "closed walks.\n\n";
    foreach my $walk (@walks_closed) {
	walk_print_single($walk);
    }
    print "# The following shows detailed information about walks\n" .
	  "# for which we have not found an end yet\n\n";
    foreach my $walk (@walks_open) {
	walk_print_single($walk);
    }
    print "# The following shows detailed information about walks " .
	  " which were timed out\n".
	  "# (no end found with timeout $timeout s)\n\n";
    foreach my $walk (@walks_timeout) {
	walk_print_single($walk);
    }
    print "# The following shows detailed information about degenerated\n".
	  "# walks (1 iterations only)\n\n";
    foreach my $walk (@walks_degen) {
	walk_print_single($walk);
    }
}

sub walk_print {
    my $pkts_closed = 0;
    my $pkts_open = 0;
    my $pkts_timeout = 0;
    my $pkts_degen = 0;

    foreach my $i (0 .. $#walks_closed) {
	$pkts_closed += $walks_closed[$i]->{'packets'};
    }
    foreach my $i (0 .. $#walks_open) {
	$pkts_open += $walks_open[$i]->{'packets'};
    }
    foreach my $i (0 .. $#walks_timeout) {
	$pkts_timeout += $walks_timeout[$i]->{'packets'};
    }
    foreach my $i (0 .. $#walks_degen) {
	$pkts_degen += $walks_degen[$i]->{'packets'};
    }

    print "# The following shows summary information about walks.\n";
    print "total packets seen: $total_packets\n";
    print "total packets belonging to walks: $walks_total_packets\n";
    print "number of walks seen: $walks_total\n";
    #print "walks properly closed: $walks_closed_ok\n";
    print "number of closed walks: ".@walks_closed.
	" ($pkts_closed packets)\n";
    print "number of open walks: ".@walks_open.
	" ($pkts_open packets)\n";
    print "number of timed out walks: ".@walks_timeout.
	" ($pkts_timeout packets)\n";
    print "number of degenerated walks: ".@walks_degen.
	" ($pkts_degen packets)\n";
    print "\n";

    # walk duration statistics calculation
    # negative durations are ignored
    my $time_min;
    my $time_max;
    my $time_avg;
    my $n = 0;
    foreach my $i (0 .. $#walks_closed) {
	my $time = $walks_closed[$i]->{'end_time'}
		- $walks_closed[$i]->{'start_time'};
	$time_avg += $time if $time >= 0;
	$n++ if $time >= 0;
	$time_min = $time if (! defined $time_min && $time >= 0);
	$time_min = $time if ($time < $time_min && $time >= 0);
	$time_max = $time if ! defined $time_max;
	$time_max = $time if ($time > $time_max);
    }
    $time_avg /= $n if $n > 0;

    print "# The following shows summary information about duration ".
	  "of closed walks.\n";
    print "average duration: $time_avg\n";
    print "min duration: $time_min\n";
    print "max duration: $time_max\n";
    print "\n";
    
    # calculate pref_count and prefs_count
    foreach my $w (@walks_closed) {
	foreach my $oid (@{$w->{'pref'}}) {
	    $pref_count{$oid}{'count'}++;
	    $pref_count{$oid}{'repetitions'} += $w->{'repetitions'};
	    $pref_count{$oid}{'interactions'} += $w->{'interactions'};
	}
	$prefs_count{join " ", @{$w->{'pref'}}}{'count'}++;
	$prefs_count{join " ", @{$w->{'pref'}}}{'repetitions'}
		+= $w->{'repetitions'};
	$prefs_count{join " ", @{$w->{'pref'}}}{'interactions'}
		+= $w->{'interactions'};
    }
    
    # table 1
    print "# table 1\n";
    print "# The following table shows following information ".
	  "for each closed walk:\n";
    print "# name - name of walk\n";
    print "# type - SNMP operation (get-next or get-bulk)\n";
    print "# intrs - number of interactions (request packets)\n";
    print "# rep - repeaters (using heurisitcs for get-next walks)\n";
    print "# nrep - non-repeaters (using heurisitcs for get-next walks)\n";
    print "# reps - sum of repetitions for all response packets\n";
    print "# resp_vbs - sum of #varbinds in all response packets\n";
    print "# duration - time of last packet minus time of first packet ".
	  "in the walk\n";
    printf("%-15s %16s %5s %5s %5s %10s %10s %10s\n",
	   "name", "type", "intrs", "rep", "nrep", "reps", "resp_vbs",
	   "duration");
    #foreach my $w ( (@walks_closed)) {
    # sort by #repetitions
    foreach my $i (sort {$walks_closed[$b]->{'repetitions'}
			 <=> $walks_closed[$a]->{'repetitions'}}
			 (0 .. $#walks_closed)) {
	my $w = $walks_closed[$i];
	printf("%-15s %16s %5s %5s %5s %10s %10s %10f\n", $w->{'name'},
	       $w->{'op'}, $w->{'interactions'}, $w->{'rep'}, $w->{'non-rep'},
	       $w->{'repetitions'}, $w->{'resp_vbs'},
	       $w->{'end_time'} - $w->{'start_time'});
    }
    print "\n";

    # table 2
    print "# table 2\n";
    print "# The following table shows OIDs starting walks.\n";
    print "# count - number of walks where this OID was in the initial ".
	  "request\n";
    print "# repetitions - sum of repetitions for all response packets ".
	  "in the walk\n";
    print "# interactions - sum of interactions for all walks as in count\n";
#    print "# resp_vbs - sum of varbinds in all response packets ".
#	  "# in the walk\n";
    printf("%-45s %10s %10s %10s\n", "OID", "count", "repetitions",
	   "interactions");
    foreach my $oid (sort {$pref_count{$b} <=> $pref_count{$a}}
		     (keys %pref_count)) {
	printf("%-45s %10d %10d %10d\n", $oid, $pref_count{$oid}{'count'},
	       $pref_count{$oid}{'repetitions'},
	       $pref_count{$oid}{'interactions'});
    }
    print "\n";
    
    # table 3
    print "# table 3\n";
    print "# The following table shows OIDs starting walks.\n".
	  "# OIDs are grouped by which OIDs have been ".
	  "in the initial request.\n";
    print "# count - number of walks where this OID was in the initial ".
	  "request\n";
    print "# repetitions - sum of repetitions for all response packets ".
	  "in the walk\n";
    print "# interactions - sum of interactions for all walks as in count\n";
#    print "# resp_vbs - sum of varbinds in all response packets ".
#	  "# in the walk\n";
    printf("%-140s %10s %10s %10s\n", "OID", "count", "repetitions",
	   "interactions");
    foreach my $oid (sort {$prefs_count{$b} <=> $prefs_count{$a}}
		     (keys %prefs_count)) {
	printf("%-140s %10d %10d %10d\n", $oid, $prefs_count{$oid}{'count'},
	       $prefs_count{$oid}{'repetitions'},
	       $prefs_count{$oid}{'interactions'});
    }
    print "\n";
}

sub process {
    $file = shift;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	$packet = $_;
	my @a = split(/,/, $_);
	walk(\@a);
    }
    filter_degenerated_walks();
    walk_print();
    walk_print_detailed if $detailed_walk_report;
    close(F);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 [-h] [-d output directory] [files|-]
      
This program tries to detect table walks in SNMP trace files in CSV format.
	
  -h            display this (help) message
  -d directory	if used, walks will be dumped into sepaprate files in directory
  -W            display detailed report for each walk
  -t seconds    timeout in seconds for discarding a walk       
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.

my %opt;
getopts( "d:t:hW", \%opt ) or usage();
usage() if defined $opt{h};
$detailed_walk_report = 1 if defined $opt{W};
$timeout = $opt{t} if defined $opt{t};
if (defined $opt{d}) {
    $dirout = $opt{d};
    if (! -e $dirout) {
	#die "Directory $dirout does not exist!\n";
	print STDERR "Directory $dirout does not exist, creating it\n";
	mkdir $dirout or die "Could not create directory $dirout\n";
    } else {
	# check if there are some files inside
    }
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
