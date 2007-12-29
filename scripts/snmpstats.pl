#!/usr/bin/perl
#
# This script computes basic statistics from CSV SNMP packet trace files.
#
# To run this script:
#    snmpstats.pl [<filename>]
#
# (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
# (c) 2006 Matus Harvan <m.harvan@iu-bremen.de>
#
# $Id$
# 

use strict;
use Getopt::Std;
use POSIX qw(strftime);

my @snmp_ops = ("get-request", "get-next-request", "get-bulk-request",
		"set-request", 
		"trap", "snmpV2-trap", "inform-request", 
		"response", "report", "");

my $meta_first = 0;
my $meta_last = 0;
my %meta_agents;
my %meta_managers;
my %meta_unknowns;

my @basic_vers;
my %basic_ops;
my %basic_errs;
my %basic_errs_max;
my %basic_nvbs;
my %basic_nvbs_max;
my %basic_size;
my %basic_bulk;
my $basic_bulk_total = 0;
my %basic_notifications;
my $basic_notifications_total = 0;
my %basic_notification_classes;

my $total = 0;
my $start = time();

my $trace_name = '';
my $flow_name = '';
my $sqlfile = '';
my $sqloutputfile;

# Below is the list of well-known subtrees. Note that the order is
# important - longer prefixes must be matched before shorter onces.

my %oid_stats;
my %oid_types;
my $oid_total = 0;
my @oid_subtrees = (
);

my %oid_transmission = (			# 1.3.6.1.2.1.10
        '7'	=> 'transmission/dot3',
       '15'	=> 'transmission/fddi',
       '18'	=> 'transmission/ds1',
       '20'	=> 'transmission/isdnMib',
       '21'	=> 'transmission/dialControlMib',
       '32'	=> 'frameRelayDTE',
       '33'	=> 'transmission/rs232',
       '35'	=> 'transmission/etherMIB',
       '39'	=> 'transmission/sonetMIB',
       '94'	=> 'transmission/adslMIB',
      '131'	=> 'transmission/tunnelMIB'
);

my %oid_mib2 = (				# 1.3.6.1.2.1
        1	=> 'mib-2/system',
        2       => 'mib-2/interfaces',
        3	=> 'mib-2/at',
        4	=> 'mib-2/ip',
        5	=> 'mib-2/icmp',
        6	=> 'mib-2/tcp',
        7	=> 'mib-2/udp',
       11	=> 'mib-2/snmp',
       14	=> 'mib-2/ospf',
       15	=> 'mib-2/bgp',
       16	=> 'mib-2/rmon',
       17	=> 'mib-2/dot1dBridge',
       24	=> 'mib-2/ipForward',
       25	=> 'mib-2/host',
       26	=> 'mib-2/snmpDot3MauMgt',
       31	=> 'mib-2/ifMIB',
       33	=> 'mib-2/upsMIB',
       37	=> 'mib-2/atmMIB',
       39	=> 'mib-2/rdbmsMIB',
       43	=> 'mib-2/printmib',
       44	=> 'mib-2/mipMIB',
       46	=> 'mib-2/dlsw',
       47	=> 'mib-2/entityMIB',
       51	=> 'mib-2/rsvp',
       55	=> 'mib-2/ipv6MIB',
       60	=> 'mib-2/accountingControlMIB',
       62	=> 'mib-2/applicationMib',
       63	=> 'mib-2/schedMIB',
       64	=> 'mib-2/scriptMIB',
       67	=> 'mib-2/radiusMIB',
       68	=> 'mib-2/vrrpMIB',
       80	=> 'mib-2/pingMIB'
);

my %oid_experimental = (			# 1.3.6.1.3
       60	=> 'experimental/ipMRouteMIB',
       61	=> 'experimental/pimMIB',
       92	=> 'experimental/msdpMIB'
);

my %oid_enterprises = (				# 1.3.6.1.4.1
        2	=> 'enterprises/ibm',
        4	=> 'enterprises/unix',
        9	=> 'enterprises/cisco',
       11	=> 'enterprises/hp',
       32	=> 'enterprises/novell',
       43	=> 'enterprises/3com',
      171	=> 'enterprises/dlink',
      522	=> 'enterprises/telesystems',
      588	=> 'enterprises/xircom',
     2021	=> 'enterprises/ucd-snmp',
     2272	=> 'enterprises/nortel',
     2522	=> 'enterprises/osicom',
     2606	=> 'enterprises/rittal',
     3076	=> 'enterprises/altiga',
     3854	=> 'enterprises/kpc',
     4714	=> 'enterprises/centerpoint',
     8072	=> 'enterprises/net-snmp',
    12394	=> 'enterprises/alvarion',
    18070	=> 'enterprises/btiphotonics'
);

my %oid_snmpModules = (				# 1.3.6.1.6.3
        1	=> 'snmpModules/snmpMIB',
       10	=> 'snmpModules/snmpFrameworkMIB',
       11	=> 'snmpModules/snmpMPDMIB',
       12	=> 'snmpModules/snmpTargetMIB',
       13	=> 'snmpModules/snmpNotificationMIB',
       14	=> 'snmpModules/snmpProxyMIB',
       15	=> 'snmpModules/snmpUsmMIB',
       16       => 'snmpModules/snmpVacmMIB',
       18	=> 'snmpModules/snmpCommunityMIB',
       19	=> 'snmpModules/snmpv2tm'
);

my %oid_ieee802dot1mibs = (			# 1.0.8802.1.1
        1       => 'ieee802dot1mibs/ieee8021paeMIB',
        2	=> 'ieee802dot1mibs/ieee8021lldp',
        3	=> 'ieee802dot1mibs/ieee8021Secy'
);


sub subtree {
    my $oid = shift;
    my $name = "";
    my @o = split('\.', $oid);
    if ($oid =~ /^1\.3\.6\.1\.2\.1\.10\./) {
	my $subid = $o[7];
	if (exists($oid_transmission{$subid})) {
	    $name = $oid_transmission{$subid};
	} else {
	    $name = "transmission/$subid";
	}
    } elsif ($oid =~ /^1\.3\.6\.1\.2\.1\./) {
	my $subid = $o[6];
	if (exists($oid_mib2{$subid})) {
	    $name = $oid_mib2{$subid};
	} else {
	    $name = "mib-2/$subid";
	}
    } elsif ($oid =~ /^1\.3\.6\.1\.3\./) {
	my $subid = $o[5];
	if (exists($oid_experimental{$subid})) {
	    $name = $oid_experimental{$subid};
	} else {
	    $name = "experimental/$subid";
	}
    } elsif ($oid =~ /^1\.3\.6\.1\.4\.1\./) {
	my $subid = $o[6];
	if (exists($oid_enterprises{$subid})) {
	    $name = $oid_enterprises{$subid};
	} else {
	    $name = "enterprises/$subid";
	}
    } elsif ($oid =~ /^1\.3\.6\.1\.6\.3\./) {
	my $subid = $o[6];
	if (exists($oid_snmpModules{$subid})) {
	    $name = $oid_snmpModules{$subid};
	} else {
	    $name = "snmpModules/$subid";
	}
    } elsif ($oid =~ /^1.0.8802.1.1/) {
	my $subid = $o[5];
	if (exists($oid_ieee802dot1mibs{$subid})) {
	    $name = $oid_ieee802dot1mibs{$subid};
	} else {
	    $name = "ieee802dot1mibs/$subid";
	}
    } else {
	$name = "unknown";
    }
    return $name;
}


sub meta {
    my $aref = shift;
    my $secs = ${$aref}[0];
    my $src = ${$aref}[1];
    my $dst = ${$aref}[3];
    my $op = ${$aref}[7];

    if ($secs > 0) {
	$meta_last = $secs;
	if ($meta_first == 0) {
	    $meta_first = $meta_last;
	}
    }

    for ($op) {
        if (/get-request|get-next-request|get-bulk-request|set-request/) {
            $meta_managers{$src}++;
            $meta_agents{$dst}++;
        } elsif (/trap|snmpV2-trap|inform-request/) {
            $meta_managers{$dst}++;
            $meta_agents{$src}++;
	} elsif (/response|report/) {
	    $meta_unknowns{$dst}++;
            $meta_unknowns{$src}++;
	} else {
	    printf("oouch\n");
        }
    }
}

sub meta_print {
    my $total = shift;
    my $gmt;
    my $sql = '';
    my $duration = $meta_last - $meta_first;
    printf("# The following table shows some overall meta information in\n" .
	   "# the form of a list of named properties.\n" .
	   "\n");
    printf("%-18s %s\n", "PROPERTY", "VALUE");

    $gmt = strftime("%FT%T+0000", gmtime($start));
    printf("%-18s %s\n", "script-start:", $gmt);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'script-start', '$gmt');\n";
    $gmt = strftime("%FT%T+0000", gmtime(time()));
    printf("%-18s %s\n", "script-end:", $gmt);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'script-end', '$gmt');\n";

    $gmt = strftime("%FT%T+0000", gmtime($meta_first));
    printf("%-18s %s\n", "trace-start:", $gmt);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-start', '$gmt');\n";
    $gmt = strftime("%FT%T+0000", gmtime($meta_last));
    printf("%-18s %s\n", "trace-end:", $gmt);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-end', '$gmt');\n";
    my $days  = int($duration/60/60/24);
    my $hours = int($duration/60/60) - $days*24;
    my $mins  = int($duration/60) - $days*24*60 - $hours*60;
    printf("%-18s %d days %d hours %d minutes\n", "trace-duration",
	   $days, $hours, $mins);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-duration', '$days days $hours hours $mins minutes');\n";
    printf("%-18s %f\n", "trace-first-time:", $meta_first);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-first-time', '$meta_first');\n";
    printf("%-18s %f\n", "trace-last-time:", $meta_last);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-last-time', '$meta_last');\n";
    printf("%-18s %s\n", "trace-messages:", $total);
    $sql .= "INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-messages', '$total');\n";

    foreach my $addr (keys %meta_unknowns) {
	if (exists $meta_managers{$addr} || exists $meta_agents{$addr}) {
	    delete $meta_unknowns{$addr};
	}
    }

    printf("%-18s %s\n", "trace-managers:", scalar keys(%meta_managers));
    $sql .= sprintf("INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-managers', '%s');\n", scalar keys(%meta_managers));
    printf("%-18s %s\n", "trace-agents:", scalar keys(%meta_agents));
    $sql .= sprintf("INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-agents', '%s');\n", scalar keys(%meta_agents));
    printf("%-18s %s\n", "trace-unknown:", scalar keys(%meta_unknowns));
    $sql .= sprintf("INSERT INTO snmp_stats_meta (trace_name, flow_name, prop_name, prop_value) VALUES ('$trace_name', '$flow_name', 'trace-unknown', '%s');\n", scalar keys(%meta_unknowns));

    # generate an SQL file, if requested:
    if ($sqlfile ne '') {
	    # delete old records (that were generated for this trace/flow name):
	    print $sqloutputfile "DELETE FROM snmp_stats_meta WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
}

sub basic {
    my $aref = shift;
    my $size = ${$aref}[5];
    my $version = ${$aref}[6];
    my $op = ${$aref}[7];
    my $err = ${$aref}[9];
    my $ind = ${$aref}[10];
    if ($err > $basic_errs_max{$op}) {
	$basic_errs_max{$op} = $err;
    }
    my $nvbs = ${$aref}[11];
    if ($nvbs > $basic_nvbs_max{$op}) {
	$basic_nvbs_max{$op} = $nvbs;
    }
    $basic_vers[$version]++;
    $basic_ops{"$version,$op"}++;
    $basic_errs{"$op,$err"}++;
    $basic_nvbs{"$op,$nvbs"}++;
    $basic_size{$op}{$size}++;
    if ($op eq "get-bulk-request") {
	$basic_bulk{"$err,$ind,$nvbs"}++;
	$basic_bulk_total++;
    }
    if ($op =~ /inform-request|trap|snmpV2-trap/) {
        if ($nvbs > 1 
            && ${$aref}[12] eq "1.3.6.1.2.1.1.3.0"
            && ${$aref}[15] eq "1.3.6.1.6.3.1.1.4.1.0") {
    	    my $uptime = ${$aref}[14];
	    my $trap = ${$aref}[17];
            my $name = subtree($trap);
            $basic_notifications{$op}{$trap}++;
            $basic_notification_classes{$op}{$name}++
        } else {
            $basic_notifications{$op}{""}++;
        }
        $basic_notifications_total++;
    }
}

sub basic_print {
    my $total = shift;
    my $sql = '';
    printf("\n" .
	   "# The following table shows the protocol operations statistics\n" .
	   "# broken down by SNMP protocol version plus the overall sums.\n" .
	   "\n");
    printf("%-18s  %14s  %14s  %14s  %14s\n", 
	   "OPERATION", "SNMPv1", "SNMPv2c", "SNMPv3", "TOTAL");
    foreach my $op (@snmp_ops) {
	printf("%-18s", "$op:");
	foreach my $version (0, 1, 3) {
	    my $val = $basic_ops{"$version,$op"};
	    printf(" %8d %5.1f%%", $val, $basic_ops{"$version,$op"}*100/$total);
	    $sql .= "INSERT INTO snmp_stats_version (trace_name, flow_name, op, snmp_ver, count) VALUES ('$trace_name', '$flow_name', '$op', '$version', '$val');\n";
	    $basic_ops{"total,$op"} += $val;
	}
	printf(" %8d %5.1f\%\n", $basic_ops{"total,$op"}, 
	       $basic_ops{"total,$op"}*100/$total);
    }
    printf("%-18s", "summary:");
    my $sum = 0;
    foreach my $version (0, 1, 3) {
	printf(" %8d %5.1f\%", $basic_vers[$version],
	       $basic_vers[$version]*100/$total);
	$sum += $basic_vers[$version];
    }
    printf(" %8d %5.1f\%\n", $sum, $sum*100/$total);

    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_version WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';
    
    printf("\n" .
	   "# The following table shows the distribution of the number of\n" .
	   "# elements in the varbind list broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %16s\n", 
	   "OPERATION", "VARBINDS", "NUMBER");
    foreach my $op (@snmp_ops) {
	for (my $i = 0; $i <= $basic_nvbs_max{$op}; $i++) {
	    if ($basic_nvbs{"$op,$i"}) {
		printf("%-18s  %12d %12d %5.1f%%\n", "$op:", $i, 
		       $basic_nvbs{"$op,$i"},
		       $basic_nvbs{"$op,$i"}*100/$total);
	    	$sql .= "INSERT INTO snmp_stats_varbind (trace_name, flow_name, op, varbinds, count) VALUES ('$trace_name', '$flow_name', '$op', '$i', '" . $basic_nvbs{"$op,$i"} . "');\n";
	    }
	}
    }

    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_varbind WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';

    printf("\n" .
	   "# The following table shows the distribution of the status\n" .
	   "# codes broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %16s\n", 
	   "OPERATION", "STATUS", "NUMBER");
    foreach my $op (@snmp_ops) {
	for (my $i = 0; $i <= $basic_errs_max{$op}; $i++) {
	    if ($basic_errs{"$op,$i"}) {
		printf("%-18s  %12d %12d %5.1f%%\n", "$op:", $i, 
		       $basic_errs{"$op,$i"},
		       $basic_errs{"$op,$i"}*100/$total);
	    	$sql .= "INSERT INTO snmp_stats_status (trace_name, flow_name, op, status, count) VALUES ('$trace_name', '$flow_name', '$op', '$i', '" . $basic_errs{"$op,$i"} . "');\n";
	    }
	}
    }

    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_status WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';

    printf("\n" .
	   "# The following table shows the distribution of the parameters\n" .
	   "# of getbulk requests.\n" .
	   "\n");
    printf("%-18s  %8s %8s %8s %16s\n", 
	   "OPERATION", "NON-REP", "MAX-REP", "VARBINDS", "NUMBER");
    foreach my $name (keys %basic_bulk) {
	my ($nonrep, $maxrep, $nvbs) = split(/,/, $name);
	printf("%-18s  %8d %8d %8d %12d %5.1f%%\n", 
	       "getbulk:", $nonrep, $maxrep, $nvbs, 
	       $basic_bulk{$name}, $basic_bulk{$name}*100/$basic_bulk_total);
	$sql .= "INSERT INTO snmp_stats_getbulk (trace_name, flow_name, op, non_rep, max_rep, varbinds, count) VALUES ('$trace_name', '$flow_name', 'getbulk', '$nonrep', '$maxrep', '$nvbs', '" . $basic_bulk{$name} . "');\n";
    }

    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_getbulk WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';

    printf("\n" .
	   "# The following table shows the distribution of notifications\n" .
	   "# types.\n" .
	   "\n");
    printf("%-12s  %-36s %16s\n", 
	   "NOTIFICATION", "OID", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $oid (sort {$a <=> $b} (keys %{$basic_notifications{$op}})) {
	    printf("%-12s  %-36s %12d %5.1f%%\n", 
		   "$op:", $oid,
		   $basic_notifications{$op}{$oid}, 
		   $basic_notifications{$op}{$oid}*100/$basic_notifications_total);
	    $sql .= "INSERT INTO snmp_stats_notification (trace_name, flow_name, op, oid, count) VALUES ('$trace_name', '$flow_name', '$op', '$oid', '" . $basic_notifications{$op}{$oid} . "');\n";
	}
    }
    
    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_notification WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';

    printf("\n" .
	   "# The following table shows the distribution of notification\n" .
	   "# types.\n" .
	   "\n");
    printf("%-12s  %-32s %16s\n", 
	   "NOTIFICATION", "SUBTREE", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $oid (sort {$a <=> $b} (keys %{$basic_notification_classes{$op}})) {
	    printf("%-12s  %-32s %12d %5.1f%%\n", 
		   "$op:", $oid,
		   $basic_notification_classes{$op}{$oid}, 
		   $basic_notification_classes{$op}{$oid}*100/$basic_notifications_total);
	}
    }
    
    printf("\n" .
	   "# The following table shows the message size distribution\n" .
	   "# broken down by operation type.\n" .
	   "\n");
    printf("%-18s  %12s  %16s\n",
	   "OPERATION", "SIZE", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $size (sort {$a <=> $b}
			  (keys %{$basic_size{$op}})) {
	    printf("%-18s  %12d  %11d %5.1f%%\n",
		   "$op:", $size, $basic_size{$op}{$size},
		   $basic_size{$op}{$size}*100/$total);
	    $sql .= "INSERT INTO snmp_stats_size (trace_name, flow_name, op, size, count) VALUES ('$trace_name', '$flow_name', '$op', '$size', '" . $basic_size{$op}{$size} . "');\n";
	}
    }
    
    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_size WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';
}

#
#
#
sub oid
{
    my $aref = shift;
    my $op = ${$aref}[7];             # snmp operation
    my $varbind_count = ${$aref}[11]; # number of varbinds in this packet
    my $name;
    for (my $i = 0; $i < $varbind_count; $i++) {
        my $oid = ${$aref}[12 + 3*$i];
        my $type = ${$aref}[13 + 3*$i];
        my $name = subtree($oid);
        $oid_stats{$op}{$name}++;
        $oid_types{$op}{$type}++;
        $oid_total++;
    }
}

#
#
#
sub oid_print
{
    return unless $oid_total;
    my $sql = '';
    printf("\n" .
	   "# The following table shows a rough classification of OIDs\n" .
	   "# according to their prefix.\n" .
	   "\n");
    printf("%-18s %-32s %15s\n", "OPERATIONS", "SUBTREE", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $name (sort {$oid_stats{$op}{$b} <=> $oid_stats{$op}{$a}}
			  (keys %{$oid_stats{$op}})) {
	    printf("%-18s %-32s %11d %5.1f%%\n", "$op:", $name, 
		   $oid_stats{$op}{$name},
		   $oid_stats{$op}{$name}*100/$oid_total);
	    $sql .= "INSERT INTO snmp_stats_oid (trace_name, flow_name, op, subtree, count) VALUES ('$trace_name', '$flow_name', '$op', '$name', '" . $oid_stats{$op}{$name} . "');\n";
	}
	if ($oid_stats{$op}{"unknown"}) {
	    printf("%-18s %-32s %11d %5.1f%%\n", "$op:", "unknown", 
		   $oid_stats{$op}{"unknown"},
		   $oid_stats{$op}{"unknown"}*100/$oid_total);
	    $sql .= "INSERT INTO snmp_stats_oid (trace_name, flow_name, op, subtree, count) VALUES ('$trace_name', '$flow_name', '$op', 'unknown', '" . $oid_stats{$op}{"unknown"} . "');\n";
	}
    }

    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_oid WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';

    printf("\n" .
	   "# The following table shows a the data types used in SNMP\n" .
	   "# operations.\n" .
	   "\n");
    printf("%-18s %-32s %15s\n", "OPERATIONS", "TYPE", "NUMBER");
    foreach my $op (@snmp_ops) {
	foreach my $type (sort {$oid_types{$op}{$b} <=> $oid_types{$op}{$a}}
			  (keys %{$oid_types{$op}})) {
	    printf("%-18s %-32s %11d %5.1f%%\n", "$op:", $type, 
		   $oid_types{$op}{$type},
		   $oid_types{$op}{$type}*100/$oid_total);
	    $sql .= "INSERT INTO snmp_stats_type (trace_name, flow_name, op, type, count) VALUES ('$trace_name', '$flow_name', '$op', '$type', '" . $oid_types{$op}{$type} . "');\n";
	}
	if ($oid_types{$op}{"unknown"}) {
	    printf("%-18s %-32s %11d %5.1f%%\n", "$op:", "unknown", 
		   $oid_types{$op}{"unknown"},
		   $oid_types{$op}{"unknown"}*100/$oid_total);
	    $sql .= "INSERT INTO snmp_stats_type (trace_name, flow_name, op, type, count) VALUES ('$trace_name', '$flow_name', '$op', 'unknown', '" . $oid_types{$op}{"unknown"} . "');\n";
	}
    }
    
    # output sql for the above table:
    if ($sqlfile ne '') {
	    print $sqloutputfile "DELETE FROM snmp_stats_type WHERE trace_name = '$trace_name' AND flow_name = '$flow_name';\n\n";
	    print $sqloutputfile $sql, "\n\n";
    }
    $sql = '';
}

#
#
#
sub process {
    my $file = shift;
    if ($file =~ /\.g|Gz|Z$/) {
	open(infile, "zcat $file |") or die "$0: Cannot open $file: $!\n";
    } elsif ($file =~ /\.bz2$/) {
	open(infile, "bzcat $file |") or die "$0: Cannot open $file: $!\n";
    } else {
	open(infile, "<$file") or die "$0: Cannot open $file: $!\n";
    }
    while (<infile>) {
	my @a = split(/,/, $_);
	meta(\@a);
	basic(\@a);
	oid(\@a);
	$total++;
    }
    close(infile);
}

#
# Print usage information about this program.
#
sub usage()
{
     print STDERR << "EOF";
Usage: $0 -n trace name -f flow name [-O file name] [-h] [files|-]
      
This program computes statistics from SNMP trace files in CSV format.
  -n trace name	name of the trace being processed
  -f flow name	name of the flow being processed (use '' for whole trace files)
  -O filename	output information to SQL filename
  -h		display this (help) message
EOF
     exit;
}

# Here is where the script basically begins. Parse the command line
# arguments and then process all files on the commandline in turn.

my %opt;
getopts( "hO:n:f:", \%opt ) or usage();
usage() if defined $opt{h};

usage() unless defined $opt{n};
usage() unless defined $opt{f};

$trace_name = $opt{n};
$flow_name = $opt{f};

if (defined $opt{O}) {
	$sqlfile = $opt{O};
	open($sqloutputfile, ">$sqlfile") or die "$0: unable to open $sqlfile: $!\n";
}

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV);
}
meta_print($total);
basic_print($total);
oid_print($total);

if ($sqlfile ne '') {
	close($sqloutputfile);
}

exit(0);
