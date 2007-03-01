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

my $outputfile;
my $dirout = "";
my $file;
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
					$total_prefix_walks2++;
				}
				else {
					#print "\n\n", $w->{'id'}, "\n\n";
				}
				$closed_walks++;

				# if we dumped walk information to a file, close that:
				if ($dirout ne "") {
					#print {$w->{'f'}} $w->{'packets'}, "/", $w->{'prefix_broke_at'}, "\n";
					#print {$w->{'f'}} "Prefix constrained: ", $w->{'prefix_constrained'}, "; Prefix broke at: ", $w->{'prefix_broke_at'}, "\n";
					close($w->{'f'});
				}

				# add the information of this walk to the output file:
				print $outputfile $w->{'id'}, ",", $w->{'strict'}, ",", $w->{'prefix_constrained'}, ",", $w->{'prefix_broke_at'}, ",", $w->{'packets'}, ",", $w->{'retransmissions'}, ",", $w->{'total_vbc'}, ",", $w->{'vbc'}, ",", join("|", @{$w->{'prefix_oids'}}), "\n";

				# put this walk into closed walks array and remove it from from the open walks array:
				push(@{$walks_closed->{$key}}, $w);
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

	#if ($total_lines > 5) {
	#	close_walks(1);
	#	print "\n\n";
	#	exit;
	#}

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
	print "Total lines: $total_lines; Walks: $total_walks; Closed: $closed_walks; Strict: $total_strict_walks; Prefix: $total_prefix_walks1; Prefix*: $total_prefix_walks2\r";

	# check if we already have a walk for this packet:
	if (defined($walks_open->{$key})) {
		#print STDERR "Found key on line $total_lines...\n";
		my $k = 0;
		#print scalar(@{$walks_open->{$key}}), "\n";
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
						print "\nWe got a retransmission...\n";
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
					# and see if the properties hold:
					if ($walk->{'op'} eq "get-bulk-request") {
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
		$w->{'id'} = $total_walks;
		$w->{'m_ip'} = $m_ip;
		$w->{'a_ip'} = $a_ip;
		$w->{'op'} = $op;
		$w->{'vbc'} = $vbc;
		$w->{'request_id'} = $request_id;
		$w->{'strict'} = 1;
		$w->{'prefix_constrained'} = 1;
		$w->{'packets'} = 0;
		$w->{'prefix_broke_at'} = 0;
		$w->{'retransmissions'} = 0;
		$w->{'non-rep'} = $err_status;
		$w->{'max-rep'} = $err_index;
		$w->{'total_vbc'} = 0;
		
		# set the prefix of this walk:
		my $offset = 0;
		if ($w->{'op'} eq "get-bulk-request") {
			$offset = $err_status * 3;
		}
		for (my $i = 0; $i < $vbc; $i++) {
			my $oid = $line[$offset + 12 + 3*$i];
			# remove trailling .0 from OIDs:
			$oid =~ s/\.0$//;
			push(@{$w->{'prefix_oids'}}, $oid);
		}

		# create a file for this walk:
		if ($dirout ne "") {
			my $f_name = "$dirout/" . basename($file) . "-$total_walks.txt";
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

	#print "[", $w->{'id'}, "]: strict: ", $w->{'strict'}, "\n";

	# how many OIDs do we have so far:
	if ($p_type eq "res") {
		$w->{'total_vbc'} += $packet_vbc;
	}
		
	# if this is a bulk request, reset non repeaters, max repetitions and
	# vbc values:
	if ($p_type eq "req" && $w->{'op'} eq "get-bulk-request") {
		$w->{'non-rep'} = $err_status;
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

		#for (my $i = 0; $i < $vbc; $i++) {
		#	print {$w->{'f'}} $w->{"last_oids_$p_type"}[$i], "\t";
		#}
		#print {$w->{'f'}} "\n";
	}
}

#
# Process a CSV file containing traces.
#
sub process_file {
	$file = shift;
	print scalar localtime(), "\n";
	open(F, "<$file") or die "$0: unable to open $file: $!\n";
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
Usage: $0 [-h] [-d output directory] [files|-]
      
This program tries to detect table walks in SNMP trace files in CSV format.
	
  -h            display this (help) message
  -d directory	if used, walks will be dumped into sepaprate files in directory
  -t seconds    timeout in seconds for discarding a walk       
  -o filename   output walk information to filename

EOF
	exit;
}

#
# Install a signal handler for SIGINT:
#
$SIG{INT} = sub {
	$interrupted = 1;
	print STDERR "got SIGINT, stopping input parsing...\n";
};

#
# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the command line in turn.
#
my %opt;
getopts("d:t:hWs:", \%opt ) or usage();
usage() if defined $opt{h};
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

my $filename = "output.csv";
if (defined $opt{o}) {
	$filename = $opt{o};
}
open(my $f, ">$filename") or die "$0: unable to open $filename: $!\n";
$outputfile = \*$f;

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
	process_file($ARGV);
}

close($outputfile);
exit(0);
