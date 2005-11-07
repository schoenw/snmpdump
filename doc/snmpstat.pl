#!/usr/bin/perl

# This script computes basic statistics from SNMP packet trace files.
#
# To run this script:
#    snmpstat.pl [<filename>]
#
# (x) 2002 Remco van de Meent    <remco@vandemeent.net>
# (x) 2005 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>

use strict;
use XML::LibXML;


sub version_stats {
    my $doc = shift;
    my @cntr;
    my $total = 0;
    foreach my $camelid ($doc->findnodes('//version')) {
	my $version = $camelid->textContent();
	$cntr[$version]++;
	$total++;
    }
    printf "SNMP version statistics:\n\n"; 
    foreach my $version (0, 1, 2) {
	printf "%18s: %5d  %3d\%\n", $version, 
	    $cntr[$version], $cntr[$version]/$total*100;
    }
    printf "    ---------------------------\n";
    printf "%18s: %5d  %3d\%\n", "total", $total, 100;
    printf "\n";
}


sub operation_stats {
    my $doc = shift;
    my @total = $doc->findnodes('//packet/snmp');
    printf "SNMP PDU type statistics:\n\n"; 
    foreach my $op ("get-request", "get-next-request", "get-bulk-request",
		    "set-request", 
		    "trap", "trap-v2", "inform", 
		    "response",
                    "report") {
	my @nodes = $doc->findnodes("//packet/snmp/$op");
	printf "%18s: %5d  %3d\%\n", $op, $#nodes + 1, 
	    ($#nodes+1)/($#total+1)*100;
    }
    printf "    ---------------------------\n";
    printf "%18s: %5d  %3d\%\n", "total", $#total + 1, 100;
    printf "\n";
}


sub oid_stats {
    my $doc = shift;
    my $oid_ctr = 0;
    my $transmission_ctr; # 1.3.6.1.2.1.10
    my $mib2_ctr;         # 1.3.6.1.2.1
    my $experiment_ctr;   # 1.3.6.1.3
    my $enterprise_ctr;   # 1.3.6.1.4.1
    foreach my $camelid ($doc->findnodes('//varbind/name')) {
        my $name = $camelid->textContent();
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
    printf "%18s: %5d  %3d\%\n", "total", $oid_ctr, 100;
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
}
exit(0);
