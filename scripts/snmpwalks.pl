#!/usr/bin/perl -w

#
# This script tries to extract talbe walks out of CSV SNMP packet
# trace files. Optionally, detected walks are written into separate
# files in specified directory.
#

use Getopt::Std;
use File::Basename;
use strict;

#
# Global variables:
#
my $total_lines = 0;		# number of lines processed
my $total_walks = 0;		# number of walks
my $closed_walks = 0;		# number of closed walks
my $walks_open = {};		# all open walks
my $walks_closed = {};		# all closed walks

my $total_strict_walks = 0;
my $total_prefix_walks1 = 0;
my $total_prefix_walks2 = 0;	# prefix property broke on last packet

my $trace_name = '';
my $flow_name = '';
my $csvoutputfile;
my $sqloutputfile;
my $dirout = "";
my $file;
my $csvfile = '';
my $sqlfile = '';
my $timeout = 0;		# timeout for walk inactivity
my $elapsed_t = 0;		# elapsed file time
my $last_t = 0;			# last recorded file time
my $interrupted;
my $packet = "";		# the current packet

#
# Compare two OIDs.
# Returns -1, 0, 1 if a < b, a == b, a > b, respectively.
#
sub oidcmp {
	my @a = split(/\./, shift);
	my @b = split(/\./, shift);
	my $i;
	for ($i = 0; $i <= $#a && $i <= $#b; $i++) {
		if ($a[$i] > $b[$i]) {
			return 1;
		}
		elsif ($a[$i] < $b[$i]) {
			return -1;
		}
	}
	if ($#a == $#b) {
		return 0;
	}
	elsif ($#a > $#b) {
		return 1;
	}
	else {
		return -1;
	}
}

#
# Given a key and an array index export the walk
# to SQL.
#
sub walk_to_sql {
	my ($key, $i) = @_;
	my $w = $walks_open->{$key}[$i];

	my $sql = '';

	# insert the walk information:
	$sql .= sprintf("INSERT INTO snmp_walk (trace_name, flow_name, cg_ip, cg_port, cr_ip, cr_port, snmp_version, snmp_operation, err_status, err_index, non_rep, max_rep, max_rep_changed, start_timestamp, end_timestamp, duration, retransmissions, vbc, response_packets, response_oids, response_bytes, request_packets, request_bytes, is_strict, is_prefix_constrained, is_strict_prefix_constr) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%f', '%f', '%f', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');\n", $trace_name, $flow_name, $w->{'m_ip'}, $w->{'m_port'}, $w->{'a_ip'}, $w->{'a_port'}, $w->{'version'}, $w->{'op'}, $w->{'err-status'}, $w->{'err-index'}, $w->{'non-rep'}, $w->{'max-rep'}, $w->{'max_rep_changed'}, $w->{'start_timestamp'}, $w->{'end_timestamp'}, $w->{'end_timestamp'} - $w->{'start_timestamp'}, $w->{'retransmissions'}, $w->{'vbc'}, $w->{'response_packets'}, $w->{'response_oids'}, $w->{'response_bytes'}, $w->{'request_packets'}, $w->{'request_bytes'}, $w->{'strict'}, $w->{'prefix_constrained'}, $w->{'strict_prefix_constrained'});

	# insert the prefixes for this walk into another table:
	my @values_arr;
	foreach my $oid (@{$w->{'prefix_oids'}}) {
		push(@values_arr, "(LAST_INSERT_ID(), '$oid')");
	}
	my $values_str = join(", ", @values_arr);
	$sql .= "INSERT INTO snmp_walk_oid (walk_id, oid) VALUES $values_str;\n";

	return $sql;
}

#
# Try to close walks (either expired or all).
# close_walks() - close all expired walks
# close_walks(1) - close all walks
#
sub close_walks {
	my $force_close = shift;
	if (!defined($force_close)) {
		$force_close = 0;
	}

	# determine what is the minimum timestamp a walk can have:
	my $min_t = $last_t - $timeout;

	# go through all walks:
	while (my ($key, $walks) = each(%{$walks_open})) {
		my $n = scalar(@{$walks});
		for (my $i = $n - 1; $i >= 0; $i--) {
			my $w = ${@{$walks}}[$i];
			# if the timeout was reached or we want to close all walks:
			if ($w->{'t'} < $min_t || $force_close eq "1") {
				# update some general statistics:
				if ($w->{'strict'} eq "1") {
					$total_strict_walks++;
				}

				if ($w->{'prefix_constrained'} eq "1") {
					$total_prefix_walks1++;
				}
				elsif ($w->{'prefix_broke_at'} == $w->{'packets'}) {
					$w->{'prefix_constrained'} = 1;
					$total_prefix_walks2++;
				}

				$closed_walks++;

				# if we dumped walk information to a file, close that:
				if ($dirout ne "") {
					close($w->{'f'});
				}

				# add the information of this walk to the output files:
				if ($csvfile ne "") {
					print $csvoutputfile $w->{'id'}, ",", $w->{'strict'}, ",", $w->{'prefix_constrained'}, ",", $w->{'prefix_broke_at'}, ",", $w->{'packets'}, ",", $w->{'retransmissions'}, ",", $w->{'response_oids'}, ",", $w->{'vbc'}, ",", join("|", @{$w->{'prefix_oids'}}), "\n";
				}

				if ($sqlfile ne "") {
					print $sqloutputfile walk_to_sql($key, $i), "\n";
				}

				# put this walk into closed walks array and remove it from from the open walks array:
				#push(@{$walks_closed->{$key}}, $w);
				splice(@{$walks}, $i, 1);
			}
		}
	}
}

#
# Process a line from the CSV file.
#
sub process_line {
	my @line = @{(shift)};
	my $t = $line[0];		# file timestamp
	my $s_ip = $line[1];		# source IP
	my $s_port = $line[2];		# source port
	my $d_ip = $line[3];		# destination IP
	my $d_port = $line[4];		# destination port
	my $size = $line[5];		# message size
	my $version = $line[6];		# SNMP version
	my $op = $line[7];		# SNMP operation
	my $request_id = $line[8];
	my $err_status = $line[9];
	my $err_index = $line[10];
	my $vbc = $line[11];		# number of variable bindings in this packet
	my $m_ip;			# manager IP
	my $m_port;			# manager port
	my $a_ip;			# agent IP
	my $a_port;			# agent port
	my $p_type;			# packet type can either be "req" (request) or "res" (response)
	my $found = 0;
	my $w;

	my $packet_vbc = $vbc;

	$total_lines++;

	# calculate elapsed file time:
	if ($total_lines > 1) {
		$elapsed_t += $t - $last_t;
	}
	$last_t = $t;
	
	#
	# if elapsed file time exceeded the timeout value, try to close
	# open walks that expired.
	#
	if ($timeout > 0 && $elapsed_t > $timeout) {
		close_walks();
		$elapsed_t = 0;
	}

	# determine $m_ip and $a_ip or exit if the operation is "uninteresting":
	if ($op =~ /get-next-request|get-bulk-request/) {
		$m_ip = $s_ip;
		$m_port = $s_port;
		$a_ip = $d_ip;
		$a_port = $d_port;
		$p_type = "req";
	}
	elsif ($op =~ /response/) {
		$m_ip = $d_ip;
		$m_port = $d_port;
		$a_ip = $s_ip;
		$a_port = $s_port;
		$p_type = "res";
	}
	else {
		return;
	}

	# create the walk key:
	my $key = "$m_ip|$a_ip";

	# print some statistics:
	# print "Total lines: $total_lines; Walks: $total_walks; Closed: $closed_walks; Strict: $total_strict_walks; Prefix: $total_prefix_walks1; Prefix*: $total_prefix_walks2;\r";

	# check if we already have a walk for this packet:
	if (defined($walks_open->{$key})) {
		#print "Array length: ", scalar(@{$walks_open->{$key}}), ";";
		#print STDERR "Found key on line $total_lines...\n";
		my $k = 0;
		WALKS: for (my $j = scalar(@{$walks_open->{$key}}) - 1; $j >= 0; $j--) {
			$k++;
			my $walk = $walks_open->{$key}[$j];
			
			# we modify the "global" variable $vbc in this loop, so reset it here:
			$vbc = $packet_vbc;

			# determine if this walk is OK:
			if (($p_type eq "req" && $walk->{'op'} eq $op) || ($p_type eq "res" && $walk->{'request_id'} eq $request_id)) {
				# we have to make sure that this packet has the same number of OIDs
				# as the current walk:
				my $offset = 0;
				if ($walk->{'op'} eq "get-bulk-request") {
					if ($p_type eq "req") {
						$vbc = $vbc - $err_status;
						$offset = $err_status * 3;
					}
					else {
						$vbc = ($vbc - $walk->{'non-rep'}) / $walk->{'max-rep'};
						$offset = $walk->{'non-rep'} * 3;
					}
				}
				if ($walk->{'vbc'} ne $vbc) {
					next WALKS;
				}

				# if this is a request packet and the walk we are looking at now 
				# is a match, but we are actually waiting for a response packet in
				# this walk, maybe this is a retransmission (it must have all OIDs
				# equal to the last OIDs seen in this walk):
				if ($p_type eq "req" && $walk->{'request_id'} ne "") {
					my $all_equal = 1;
					for (my $i = 0; $i < $vbc; $i++) {
						my $oid = $line[$offset + 12 + 3*$i];
						my $last_oid_req = $walk->{'last_oids_req'}[$i];
						$oid =~ s/\.0$//;
						if (oidcmp($oid, $last_oid_req)) {
							#print "\nRequest packet seemed like retransmission...\n";
							$all_equal = 0;
							next WALKS;
						}
					}
					# we got a retransmission:
					if ($all_equal) {
						print "\nRETRANSMISSION: on line ", $total_lines, " for packet on line ", $walk->{'last_request_line'}, " after ", $t - $walk->{'last_request_t'}, " seconds\n";
						print "$packet\n";
						$walk->{'retransmissions'}++;
						return;
					}
				}

				my $strict = 0;
				my $prefix_constrained = 0;

				my $all_prefix_constrained = 1;
				my $one_increasing = 0;
				my $all_non_decreasing = 1;
				my $all_equal = 1;
				my $one_equal = 0;

				# go through all OIDs of this packet:
				for (my $i = 0; $i < $vbc; $i++) {
					my $oid = $line[$offset + 12 + 3*$i];
					my $prefix = $walk->{'prefix_oids'}[$i];
					
					# check for all prefix constrained:
					if (!($oid =~ /^$prefix/)) {
						$all_prefix_constrained = 0;
					}

					# checks done for request packets:
					if ($p_type eq "req") {
						my $last_oid_req = $walk->{'last_oids_req'}[$i];
						my $last_oid_res = $walk->{'last_oids_res'}[$i];

						my $cmp_req = oidcmp($oid, $last_oid_req);
						my $cmp_res = oidcmp($oid, $last_oid_res);

						if ($cmp_req > 0) {
							$one_increasing = 1;
						}
						elsif ($cmp_req < 0) {
							$all_non_decreasing = 0;
						}

						if ($cmp_res == 0) {
							$one_equal = 1;
						}
						else {
							$all_equal = 0;
						}
					}
					# checks done for response packets:
					elsif ($p_type eq "res") {
						my $last_oid_req = $walk->{'last_oids_req'}[$i];
						my $cmp_req = oidcmp($oid, $last_oid_req);

						if ($cmp_req < 0) {
							$all_non_decreasing = 0;
						}
					}
				}


				# checks for request packets:
				if ($p_type eq "req") {
					# generalized walk:
					if ($one_equal && $one_increasing && $all_non_decreasing) {
						$found = 1;
					}

					if ($found) {
						# prefix constrained walk:
						if ($all_prefix_constrained) {
							$prefix_constrained = 1;
						}

						# strict walk:
						if ($all_equal) {
							$strict = 1;
						}
					}
				}
				# checks for response packets:
				elsif ($p_type eq "res") {
					# we don't care if this is a "good" packet, since
					# we have the request_id the same as in the request
					# packet.
					$found = 1;

					# if this is a bulk request, go through all repetitions
					# and see if the "prefix" and "non-decreasing" properties hold:
					if ($walk->{'op'} eq "get-bulk-request") {
						my $repetitions = ($packet_vbc - $walk->{'non-rep'}) / $vbc;
						my $offset = $walk->{'non-rep'} * 3;
						my @last_oids;
						for (my $k = 0; $k < $vbc; $k++) {
							push(@last_oids, $walk->{'last_oids_req'}[$k]);
						}

						for (my $k = 0; $k < $repetitions; $k++) {
							for (my $j = 0; $j < $vbc; $j++) {
								my $oid = $line[$offset + 12 + $j*3];
								my $last_oid = $last_oids[$j];
								my $prefix = $walk->{'prefix_oids'}[$j];

								# check if prefix is OK for the OIDs in all
								# repetitions:
								if (!($oid =~ /^$prefix/)) {
									$all_prefix_constrained = 0;
								}

								# check if this OID is greater than the one
								# in the previous repetition:
								if (oidcmp($oid, $last_oid) < 0) {
									$all_non_decreasing = 0;
								}

								# set this OID as the "last" OID, for the next
								# time we execute this loop:
								$last_oids[$j] = $oid;
							}

							# we increase the offset for each new repetition:
							$offset += $vbc * 3;
						}
					}

					# prefix constrained walk:
					if ($all_prefix_constrained) {
						$prefix_constrained = 1;
					}
					
					# is this a "bad" response packet?
					if (!$all_non_decreasing) {
						print STDERR "\n\nReceived a bad response packet...\n\n";
					}
				}

				# if we found some walk, quit WALKS loop:
				# we also make some updates on the walk here, otherwise we
				# will loose the loop-local variables:
				if ($found) {
					$w = $walk;
					# if we lost the prefix constrained property now, record the packet number:
					if ($w->{'prefix_constrained'} == 1 && !$prefix_constrained) {
						$w->{'prefix_constrained'} = 0;
						$w->{'strict_prefix_constrained'} = 0;
						$w->{'prefix_broke_at'} = $w->{'packets'} + 1;
					}

					# strict property can only be lost on request packets:
					if ($w->{'strict'} == 1 && !$strict && $p_type eq "req") {
						$w->{'strict'} = 0;
					}
					last WALKS;
				}
			}
		}
		#print STDERR "For loop went for $k steps...\n";
	}
	else {
		if ($p_type eq "req") {
			#print STDERR "New key '$key'...\n";
		}
		# if we don't get a key for a response packet it means
		# we didn't have a request, or something is wrong:
		elsif ($p_type eq "res") {
			#print STDERR "Key '$key' not found for response packet...\n";
		}
	}
	
	# if we found a walk, update its information:
	if ($found) {
		# updates made for request packets:
		if ($p_type eq "req") {
			$w->{'request_id'} = $request_id;
		}
		# updates made for response packets:
		elsif ($p_type eq "res") {
			$w->{'request_id'} = "";
		}
	}
	# if this is a new walk and a get next/bulk packet, add it to the list:
	elsif ($p_type eq "req") {
		#print STDERR "\nNew walk found on line $total_lines...\n";
		$found = 1;
		$total_walks++;
		$w = {};
		$w->{'last_request_line'} = $total_lines;
		$w->{'last_request_t'} = $t;
		$w->{'start_timestamp'} = $t;
		$w->{'id'} = $total_walks;
		$w->{'m_ip'} = $m_ip;
		$w->{'m_port'} = $m_port;
		$w->{'a_ip'} = $a_ip;
		$w->{'a_port'} = $a_port;
		$w->{'version'} = $version;
		$w->{'op'} = $op;
		$w->{'vbc'} = $vbc;
		$w->{'request_id'} = $request_id;
		$w->{'strict'} = 1;
		$w->{'prefix_constrained'} = 1;
		$w->{'strict_prefix_constrained'} = 1;
		$w->{'packets'} = 0;
		$w->{'prefix_broke_at'} = 0;
		$w->{'retransmissions'} = 0;
		$w->{'err-status'} = 0;
		$w->{'err-index'} = 0;
		$w->{'non-rep'} = $err_status;
		$w->{'max-rep'} = $err_index;

		$w->{'response_bytes'} = 0;
		$w->{'response_packets'} = 0;
		$w->{'response_oids'} = 0;

		$w->{'request_packets'} = 0;
		$w->{'request_bytes'} = 0;

		$w->{'max_rep_changed'} = 0;

		# set the prefix of this walk:
		my $offset = 0;
		if ($w->{'op'} eq "get-bulk-request") {
			$offset = $err_status * 3;
			$w->{'err-status'} = 0;
			$w->{'err-index'} = 0;
		}
		else {
			$w->{'non-rep'} = 0;
			$w->{'max-rep'} = 0;
		}

		for (my $i = 0; $i < $vbc; $i++) {
			my $oid = $line[$offset + 12 + 3*$i];
			# remove trailling .0 from OIDs:
			$oid =~ s/\.0$//;
			push(@{$w->{'prefix_oids'}}, $oid);
		}

		# create a file for this walk:
		if ($dirout ne "") {
			my $f_name = "$dirout/" . basename($file) . "-$total_walks.csv";
			open(my $f, ">$f_name") or die "$0: unable to open $f_name: $!\n";
			$w->{'f'} = \*$f;
		}

		# add this walk to the open walks list:
		push(@{$walks_open->{$key}}, $w);
	}

	#
	# at this point we must have a walk, either new or an older one.
	#
	if (!$found) {
		return;
	}

	$w->{'end_timestamp'} = $t;

	# how many OIDs do we have so far:
	if ($p_type eq "res") {
		$w->{'response_packets'}++;
		$w->{'response_bytes'} += $size;
		$w->{'response_oids'} += $packet_vbc;
		$w->{'err-status'} = $err_status;
		$w->{'err-index'} = $err_index;
	}
	else {
		$w->{'last_request_line'} = $total_lines;
		$w->{'last_request_t'} = $t;
		$w->{'request_packets'}++;
		$w->{'request_bytes'} += $size;
	}
		
	# if this is a bulk request, reset non repeaters, max repetitions and
	# vbc values:
	if ($p_type eq "req" && $w->{'op'} eq "get-bulk-request") {
		$w->{'non-rep'} = $err_status;
		if ($w->{'max-rep'} ne $err_index) {
			$w->{'max_rep_changed'} = 1;
		}
		$w->{'max-rep'} = $err_index;
		$w->{'vbc'} = $packet_vbc - $w->{'non-rep'};	# I'm not sure we need this updated!!!
	}

	# determine how many repetitions we have in this packet (it will be 1
	# by default, the case of get-next-requests:
	my $repetitions = 1;

	if ($p_type eq "res" && $w->{'op'} eq "get-bulk-request") {
		$repetitions = ($packet_vbc - $w->{'non-rep'}) / $w->{'vbc'};
	}

	# set the latest OIDs:
	# we need an offset, that will take us straight to the last OIDs in
	# this packet, which is calculated below:
	my $offset = (($repetitions - 1) * $w->{'vbc'} + $w->{'non-rep'}) * 3;
	for (my $i = 0; $i < $w->{'vbc'}; $i++) {
		my $oid = $line[$offset + 12 + 3*$i];
		# remove trailling .0 from OIDs:
		$oid =~ s/\.0$//;
		$w->{"last_oids_$p_type"}[$i] = $oid;
	}

	# update other information for this walk:
	$w->{'t'} = $t;
	$w->{'packets'}++;

	# add this packet to the walk file:
	if ($dirout ne "") {
		print {$w->{'f'}} $packet;
	}

}

#
# Process a CSV file containing traces.
#
sub process_file {
	$file = shift;

	# in case we need to export to SQL, delete all previous records generated
	# from this file:
	if ($sqlfile ne '') {
		print $sqloutputfile "DELETE t1, t2 FROM snmp_walk AS t1, snmp_walk_oid AS t2 WHERE t1.trace_name = '$trace_name' AND t1.flow_name = '$flow_name' AND t2.walk_id = t1.id;\n\n";
	}

	print scalar localtime(), "\n";

    	if ($file =~ /\.g|Gz|Z$/) {
		open(F, "zcat $file |") or die "$0: Cannot open $file: $!\n";
	}
	elsif ($file =~ /\.bz2$/) {
		open(F, "bzcat $file |") or die "$0: Cannot open $file: $!\n";
	}
	else {
		open(F, "<$file") or die "$0: Cannot open $file: $!\n";
	}
	while (<F>) {
		$packet = $_;
		my @line = split(/,/);
		process_line(\@line);
		last if $interrupted;
	}
	close(F);
	close_walks(1);

	print "\n";
	print scalar localtime(), "\n";
}

#
# Print usage information about this program.
#
sub usage() {
	print STDERR << "EOF";
Usage: $0 -n trace name -f flow name [-t timeout] [-d output directory] [-o file] [-O file] [-h] [files|-]
      
This program tries to detect table walks in SNMP trace files in CSV format.
	
  -n trace name name of the trace being processed
  -f flow name	name of the flow being processed (use '' for whole trace files)
  -t seconds    timeout in seconds for discarding a walk       
  -d directory	if used, walks will be dumped into separate files in directory
  -o filename   output walk information to CSV filename
  -O filename   output walk information to SQL filename
  -h            display this (help) message

EOF
	exit;
}

#
# Install a signal handlers for properly terminating the
# script and printing some status information.
#
$SIG{INT} = sub {
	$interrupted = 1;
	print STDERR "got SIGINT, stopping input parsing...\n";
};

$SIG{HUP} = sub {
    print STDERR "lines: $total_lines; walks: $total_walks; closed: $closed_walks; strict: $total_strict_walks; prefix: $total_prefix_walks1; prefix*: $total_prefix_walks2;\n";
};

#
# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the command line in turn.
#
my %opt;
getopts("ht:d:o:O:n:f:", \%opt ) or usage();

usage() if defined $opt{h};
usage() unless defined $opt{n};
usage() unless defined $opt{f};

$trace_name = $opt{n};
$flow_name = $opt{f};

$timeout = 20;
$timeout = $opt{t} if defined $opt{t};

if (defined $opt{d}) {
	$dirout = $opt{d};
	if (! -e $dirout) {
		print STDERR "Directory '$dirout' does not exist, creating it...\n";
		mkdir $dirout or die "Could not create directory $dirout.\n";
	}
	else {
		# check if there are some files inside
	}
}

if (defined $opt{o}) {
	$csvfile = $opt{o};
	open($csvoutputfile, ">$csvfile") or die "$0: unable to open $csvfile: $!\n";
}

if (defined $opt{O}) {
	$sqlfile = $opt{O};
	open($sqloutputfile, ">$sqlfile") or die "$0: unable to open $sqlfile: $!\n";
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
	$total_lines = 0;
	process_file($ARGV);
}

if ($csvfile ne "") {
	close($csvoutputfile);
}

if ($sqlfile ne "") {
	close($sqloutputfile);
}

exit(0);
