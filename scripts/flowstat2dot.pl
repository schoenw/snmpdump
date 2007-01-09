#!/usr/bin/perl
#
# This script converts the output produced by the snmpflowstats.pl
# script into a dot file for the graphviz package.
#
# Example: perl flowstats2dot.pl <flowstatsfile>
#
# (c) 2007 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
#
# $Id: snmpstats.pl 1974 2006-08-14 21:33:07Z schoenw $
# 

use strict;
use File::Basename;

my %node_a;
my %node_m;
my $node_a_cnt = 0;
my $node_m_cnt = 0;

my %edges_m;
my %edges_a;

my $dot_name;

my $start = time();

# *********** print functions *************

sub agent
{
    my $ip = shift;
    if (! exists($node_a{$ip})) {
	$node_a{$ip} = $node_a_cnt++;
    }
    
    return "a$node_a{$ip}";
}

sub manager
{
    my $ip = shift;
    if (! exists($node_m{$ip})) {
	$node_m{$ip} = $node_m_cnt++;
    }
    
    return "m$node_m{$ip}";
}

sub dot_print
{
    printf("digraph %s {\n" .
	   "\n" .
	   "  label=\"SNMP flow graph for trace %s\";\n" .
	   "  splines=true;\n" .
	   "  overlap=false;\n" .
	   "\n",
	   $dot_name, $dot_name);

    printf("  node [shape=point];\n");
    foreach my $ip (keys %node_m) {
	printf("  m%s [shape=circle, style=bold];\n", $node_m{$ip});
    }
    printf("\n");

    printf("  subgraph m {\n" .
	   "\n" .
	   "    edge [color=\"green\", arrowsize=0.5];\n" .
	   "\n");
    foreach my $edge (keys %edges_m) {
	printf("    %s;\n", $edge);
    }
    printf("  }\n\n");

    printf("  subgraph m {\n" .
	   "\n" .
	   "    edge[color=\"red\", style=\"dashed\", arrowsize=0.5];\n" .
	   "\n");
    foreach my $edge (keys %edges_a) {
	printf("    %s;\n", $edge);
    }
    printf("  }\n\n");

    printf("}\n");
}

sub process
{
    my $file = shift;
    my $name = basename($file);
    if ($file =~ /\.g|Gz|Z$/) { 
	open(infile, "zcat $file |") or die "$0: Cannot open $file: $!\n";
    } else {
	open(infile, $file) || die "$0: Cannot open $file: $!";
    }
    my $inrevision = 0;

    $dot_name = $name;
    $dot_name =~ s/-.*//;
    while (<infile>) {
	chomp;
	if (/^NUMBER.*DURATION.*MESSAGES.*BYTES.*FLOW$/) {
	    $inrevision = 1;
	    next;
	} elsif ($inrevision) {
	    if ($_ =~ /^(\s)*$/) { next; }
	    my ($number, $duration, $messages, $bytes, $mpm, $bpm, $flow) 
		= split(' ', $_);
	    $flow =~ s/.gz$//;
	    $flow =~ s/.csv$//;
	    my ($trace, $src_type, $src_name, $dst_type, $dst_name) 
		= split('-',$flow);
	    $src_name =~ s/\./_/g;
	    $dst_name =~ s/\./_/g;
	    if ($src_name =~ /^(\s)*$/) { next; }
	    if ($dst_name =~ /^(\s)*$/) { next; }

	    if ($src_type eq "cg" && $dst_type eq "cr") {
		my $a = manager($src_name);
		my $b = agent($dst_name);
		$edges_m{"$a -> $b"} = 42;
	    }
	    if ($src_type eq "no" && $dst_type eq "nr") {
		my $a = agent($src_name);
		my $b = manager($dst_name);
		$edges_a{"$a -> $b"} = 42;
	    }
	}
    }
    close(infile);
}


# *********** MAIN *************

@ARGV = ('-') unless @ARGV;
while ($ARGV = shift) {
    process($ARGV)
}
dot_print();
exit(0);
