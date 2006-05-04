#!/bin/bash
#
# Shell script to run snmpdump on pcap files and produce xml and csv
# files.
#
# $Id$
#

SNMPDUMP=../src/snmpdump

produce_xml()
{
    for file in *.pcap; do
	echo -n "processing (xml) $file..."
	$SNMPDUMP -o xml $file \
	    | xmllint --format - > `basename $file pcap`xml
	echo "done"
    done
}

produce_csv()
{
    for file in *.pcap; do
	echo -n "processing (csv) $file..."
	$SNMPDUMP -o csv $file > `basename $file pcap`csv
	echo "done"
    done
}

produce_xml
produce_csv
