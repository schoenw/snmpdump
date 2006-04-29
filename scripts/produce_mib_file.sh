#!/bin/sh
#
# Produces mib file which can be used by snmpstat.pl to create oid to
# name mappings.

MIBS="SNMPv2-MIB IF-MIB IP-MIB IP-FORWARD-MIB UDP-MIB TCP-MIB"
MIBS="$MIBS SNMP-FRAMEWORK-MIB SNMP-VIEW-BASED-ACM-MIB"
MIBS="$MIBS HOST-RESOURCES-MIB Printer-MIB"

OUTFILE=mib-identifiers.txt

rm -f $OUTFILE

for f in $MIBS ; do
    smidump -f identifiers $f | grep -v "group|compliance" >> $OUTFILE
done
