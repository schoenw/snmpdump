#!/bin/sh
#
# Produces mib file which can be used by snmpstat.pl to create oid to
# name mappings.

MIBS="IF-MIB"
OUTFILE=mib

smidump -f identifiers $MIBS > $OUTFILE
