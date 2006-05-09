#!/usr/bin/perl
#
# This script tries to extract talbe walks out of CSV SNMP packet
# trace files. Detected walks are written into separate files in
# specified output directory.
#

# A walk is defined as a series of get-next/response or
# get-bulk/response operations. Oids in the requests in the same
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

# BUGS:

# If we miss the first walk request, we probably miss also the oid
# prefix. We could figure out the prefix also later on during the walk
# by checking MIB information, but we're not doing it at the moment.

# We do not distinguish two concurrent walks for the same OID prefix.

# The above definition of a walk may miss some non-standard walks. IT
# is questionabble whether these really should be considered walks.

# If columns are of different length and the agent would wrap back to
# the beginning of the table, we would probably notnotice the end of
# the walk

# TODO:

# o dump walks into separate files, use only basename of file
# o don't dump walks of length 1
# o cleanup code
# o get-bulk support
# o 1 request, 2 responses

#
# To run this script:
#    snmpwalks.pl [-d directory] [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id: snmpstats.pl 1911 2006-04-29 22:47:00Z harvan $
# 

use Getopt::Std;
use File::Basename;
use strict;

my @snmp_ops = ("get-request", "get-next-request", "get-bulk-request",
		"set-request", 
		"trap", "trap2", "inform", 
		"response", "report", "");

my @basic_vers;
my %basic_ops;
my %basic_errs;
my %basic_errs_max;
my %basic_nvbs;
my %basic_nvbs_max;

my %oid_name;		# oid to name mapping
my %varbind_count;	# hash (by operation) of hashes (by varbinds)
my %oid_count;		# hash (by operation) of hashes (by oids)
my %oid_unidentified;	# varbinds for which we have not found a matching oid
			# hash (by operation) of hashes (by varbinds) 
my @oid_op_total;	# how many varbinds have we seen for each operation
			# (includes also unidentified varbinds)

my @walks_open;		# open walks, array of hashes of:
			# manag_ip, agent_ip, varbind_count,
			# @pref, @last_oid
my $walks_total;
my $walks_total_packets;
my $walks_holes;
my $walks_closed_ok;
my $walks_closed_heur;
my $walk_nonwalk_packets;

my $dirout = "walks";  # directory where the walk files should go
my $file;	       # currently processed input file
my $packet;	       # string representing the original packet as read
		       # from the CSV file

# We need the following information to identify a walk:
# o manager IP
# o agent IP
# o number of varbinds
# o OID prefix (array)
# o last requested OID (array)
# o last request ID
# o ? SNMP version

# additionally we keep the following information about a walk:
# o first packet (request), unless written already
# o number of packets (length of walk)
# o number of holes seen
# o file handle for output
# o walk ID

#
# compare two oids a, b as strings
# returns -1, 0, 1 if a < b, a == b, a > b, respectively
#
sub cmp_oids {
    my $a = shift;
    my $b = shift;
    my @a = split('.', $a);
    my @b = split('.', $b);
    for (my $i = 0; $i < @a && $i < @b && $a[$i] == $b[$i];  $i++) {
	if ($a[$i] > $b[$i]) {
	    return 1;
	} else {
	    return -1;
	}
    }
    return 0;
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
    my $err = ${$aref}[9];
    my $varbind_count = ${$aref}[11]; # number of varbinds in this packet
    my $manag_ip;
    my $agent_ip;
    my $found = 0;
    my %walk;
    my $walk;

    if ($op =~ /get-next-request/) { #/get-next-request|get-bulk-request/
	$manag_ip = $from;
	$agent_ip = $to;
	foreach my $w ( @walks_open ) {
	    if ($w->{"manag_ip"} == $manag_ip
		&& $w->{"agent_ip"} == $agent_ip
		#&& $walk["op"] == $op
		&& $w->{"varbind_count"} == $varbind_count) {
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
	    #print "found walk: $walk->{'manag_ip'}\n";
	    # existing walk
# 	    print "packet oids: ";
# 	    print "@{$walk->{'last_oid'}}";
# 	    print "\n matched to walk with oid prefixes: ";
# 	    print "@{$walk->{'pref'}}";
# 	    print "\n";
	    for (my $i = 0; $i < $varbind_count; $i++) {
		my $oid =  ${$aref}[12 + 3*$i];
		$walk->{"last_oid"}[$i] = $oid;
	    }
	    $walk->{"request_id"} = $request_id;
	    $walk->{"length"}++;
 	    #print {$walk->{"F"}} join(",",@{$aref});
 	    print {$walk->{"F"}} $packet;
	} else {
	    # first packet of a walk
	    $walks_total++;
	    my $filename = $dirout."/".basename($file)."-$walks_total";
 	    open(my $f, ">$filename")
		or die "$0: unable to open $filename: $!\n";
 	    $walk{"F"} = \*$f;
 	    #$walk{"F"} = \*F;
 	    #print F join(",", @{$aref});
 	    #print {$walk{"F"}} join(",", @{$aref});
 	    print {$walk{"F"}} $packet;
	    $walk{"manag_ip"} = $manag_ip;
	    $walk{"agent_ip"} = $agent_ip;
	    #$walk["op"] = $op;
	    $walk{"varbind_count"} = $varbind_count;
	    for (my $i = 0; $i < $varbind_count; $i++) {
		my $oid =  ${$aref}[12 + 3*$i];
		$walk{"pref"}[$i] = $oid;
		$walk{"last_oid"}[$i] = $oid;
	    }
	    $walk{"request_id"} = $request_id;
	    $walk{"length"}++;
	    push(@walks_open, { %walk });
	    print "packet starting a new walk, oids: ";
	    print "@{$walk{'pref'}}";
	    print "\n";   
	}
    }
    if ($op =~ /response/) {
	# match to request (probably last active walk)
	$manag_ip = $to;
	$agent_ip = $from;
	my $prefix_match = 0;
	foreach my $w ( @walks_open ) {
	    if ($w->{"manag_ip"} == $manag_ip
		&& $w->{"agent_ip"} == $agent_ip
		#&& $walk["op"] == $op
		&& $w->{"varbind_count"} == $varbind_count
		&& $w->{"request_id"} == $request_id) {
		# are OIDs lex. >= than in previous request ?
		for (my $i = 0; $i < $varbind_count; $i++) {
		    my $oid =  ${$aref}[12 + 3*$i];
		    my $last_oid =  $w->{"last_oid"}[$i];
		    my $pref = $w->{"pref"}[$i];
		    if (cmp_oids($oid, $last_oid) > 0 ) {
			$found = 1;
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
	    $walk->{"length"}++;
 	    #print {$walk->{"F"}} join(',',@{$aref});
 	    print {$walk->{"F"}} $packet;
	    # do OIDs match the prefix?
	    for (my $i = 0; $i < $varbind_count; $i++) {
		my $oid =  ${$aref}[12 + 3*$i];
		my $pref = $walk->{"pref"}[$i];
		if ($oid =~ /^$pref/) {
		    $prefix_match = 1;
		}
	    }
	    if (! $prefix_match) {
		print "walk ended - out of prefix (${$aref}[12])\n";
		$walks_closed_ok++;
		print "walk length: $walk->{'length'}, " .
		      " varbind_count: $walk->{'varbind_count'}\n";
		for (my $i=0; $i<@walks_open;$i++) {
		    if ($walks_open[$i] ==  $walk) {
			$walks_total_packets++;
			delete $walks_open[$i];
			last;
		    }
		}
	    }
	} else {
	    # response does not belong to an open walk
	    #print "could not match response to a walk\n";
	}
	# optional: try to detect holes
    }
}

sub walk_print {
    my $total = shift;
    print "walks properly closed: $walks_closed_ok\n\n";
    print "open walks: ".@walks_open."\n";
    foreach my $walk (@walks_open) {
	print "oid prefix: @{$walk->{'pref'}}\n" .
	    "walk length: $walk->{'length'}\n" .
	    "varbind_count: $walk->{'varbind_count'}\n";
	
    }
}

sub process {
    $file = shift;
    my $total = 0;
    open(F, "<$file") or die "$0: unable to open $file: $!\n";
    while (<F>) {
	$packet = $_;
	my @a = split(/,/, $_);
	walk(\@a);
	$total++;
    }
    walk_print($total);
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
  -d directory	where should the alk files go
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.

my %opt;
getopts( "d:h", \%opt ) or usage();
usage() if defined $opt{h};
if (defined $opt{d}) {
    $dirout = $opt{d};
    if (-e $dirout) {
	# check if there are some files inside
    } else {
	mkdir $dirout;
    }
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
exit(0);
