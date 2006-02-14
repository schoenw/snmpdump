#!/usr/bin/perl

# This script computes basic statistics from SNMP packet trace files.
#
# To run this script:
#    snmpstat.pl [<filename>]
#
# (c) 2002 Remco van de Meent    <remco@vandemeent.net>
# (c) 2005 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>

use strict;
use XML::LibXML;


sub version_stats {
    my $doc = shift;
    my @cntr;
    my $total = 0;
    foreach my $node ($doc->findnodes('//snmp/version')) {
	my $version = $node->textContent();
	$cntr[$version]++;
	$total++;
    }
    printf "SNMP version statistics:\n\n"; 
    foreach my $version (0, 1, 2) {
	printf "%18s: %5d  %3d\%\n", $version, 
	    $cntr[$version], $cntr[$version]/$total*100;
    }
    printf "    ---------------------------\n";
    printf "%18s: %5d  %3d\%\n\n", "total", $total, 100;
}


sub operation_stats {
    my $doc = shift;
    my @total = $doc->findnodes('//packet/snmp');
    printf "SNMP PDU type statistics:\n\n"; 
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap-v2", "inform", 
		    "response", "report") {
	my @nodes = $doc->findnodes("//packet/snmp/$op");
	printf "%18s: %5d  %3d\%\n", $op, $#nodes + 1, 
	    ($#nodes+1)/($#total+1)*100;
    }
    printf "    ---------------------------\n";
    printf "%18s: %5d  %3d\%\n\n", "total", $#total + 1, 100;
}


sub oid_stats {
    my $doc = shift;
    my $oid_ctr = 0;
    my $transmission_ctr; # 1.3.6.1.2.1.10
    my $mib2_ctr;         # 1.3.6.1.2.1
    my $experiment_ctr;   # 1.3.6.1.3
    my $enterprise_ctr;   # 1.3.6.1.4.1
    foreach my $node ($doc->findnodes('//varbind/name')) {
        my $name = $node->textContent();
	for ($name) {
	    if    (/1\.3\.6\.1\.2\.1\.10/) { $transmission_ctr++; }
	    elsif (/1\.3\.6\.1\.2\.1/)     { $mib2_ctr++; }
	    elsif (/1\.3\.6\.1\.3/)        { $experiment_ctr++; }
	    elsif (/1\.3\.6\.1\.4\.1/)     { $enterprise_ctr++; }
	}
	$oid_ctr++;
    }
    printf "SNMP OID prefix statistics:\n\n"; 
    printf "%18s: %5d  %3d\%\n", "transmission",
        $transmission_ctr, ($transmission_ctr/$oid_ctr*100);
    printf "%18s: %5d  %3d\%\n", "mib-2",
        $mib2_ctr, ($mib2_ctr/$oid_ctr*100);
    printf "%18s: %5d  %3d\%\n", "experimental",
        $experiment_ctr, ($experiment_ctr/$oid_ctr*100);
    printf "%18s: %5d  %3d\%\n", "enterprises",
        $enterprise_ctr, ($enterprise_ctr/$oid_ctr*100);
    printf "    ---------------------------\n";
    printf "%18s: %5d  %3d\%\n\n", "total", $oid_ctr, 100;
}


sub size_stats {
    my $doc = shift;
    my @total = $doc->findnodes('//packet/snmp');
    printf "SNMP message size statistics:\n\n"; 
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap-v2", "inform", 
		    "response", "report") {
	my $total_ops = 0;
	my $total_len = 0;
	foreach my $node ($doc->findnodes("//packet/snmp/$op")) {
	    my @msg_len = $node->find('../@blen');
	    $total_ops++;
	    # $total_len += $msg_len[0];
	    # printf "\t%d\t%d\n", @msg_len, $total_len;
	}
	printf "%18s: %5d %5d %f\n", $op, $total_ops, $total_len, $total_ops ? $total_len/$total_ops : 0;
    }
    printf "\n";
}


sub min {
    if ($_[0]>$_[1]) {return $_[1]} else {return $_[0]};
}

sub max {
    if ($_[0]<$_[1]) {return $_[1]} else {return $_[0]};
}

sub varbind_stats {
    my $doc = shift;
    my @total = $doc->findnodes('//packet/snmp');
    printf "SNMP varbind number statistics:\n\n"; 
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", "trap", "trap-v2", "inform", 
		    "response", "report") {
	my ($total_ops, $total_vbs, $total_vbs_min, $total_vbs_max);
	foreach my $node ($doc->findnodes("//packet/snmp/$op")) {
	    my @varbinds = $node->findnodes("variable-bindings/varbind");
	    $total_ops++;
	    $total_vbs += $#varbinds + 1;
	    $total_vbs_min = min($total_vbs_min, $#varbinds + 1);
	    $total_vbs_max = max($total_vbs_max, $#varbinds + 1);
	}
	printf "%18s: %5d %5d %5.2f %5d %5d\n", $op, $total_ops, $total_vbs, $total_ops ? $total_vbs/$total_ops : 0, $total_vbs_min, $total_vbs_max;
    }
    printf "\n";
}


@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    my $parser = XML::LibXML->new();
    my $tree = $parser->parse_file($ARGV);
    my $doc = $tree->getDocumentElement;
    
    version_stats($doc);
    operation_stats($doc);
    oid_stats($doc);
    size_stats($doc);
    varbind_stats($doc);
}
exit(0);
