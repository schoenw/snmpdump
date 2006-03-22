#!/bin/sh
#
# Shell script for regression testing snmpdump. More tests are always
# welcome. :)
#
# $Id$
#

SNMPDUMP=../src/snmpdump

test_pcap_reader()
{
    for file in *.pcap; do
	$SNMPDUMP -i pcap -o xml $file \
	    | xmllint --format - \
	    | diff -u `basename $file .pcap`.xml -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_xml_reader()
{
    for file in *.xml; do
	$SNMPDUMP -i xml -o xml $file \
	    | xmllint --format - \
	    | diff -u $file -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_csv_writer()
{
    for file in *pcap; do
	$SNMPDUMP -i pcap -o csv $file \
	    | diff -u `basename $file .pcap`.csv -
	if [ $? == 0 ]; then
            echo "$FUNCNAME: $file: PASSED"
        else
            echo "$FUNCNAME: $file: FAILED"
        fi
    done
}

test_pcap_reader
echo ""
test_xml_reader
echo ""
test_csv_writer
