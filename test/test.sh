#!/bin/bash
#
# Shell script for regression testing snmpdump. More tests are always
# welcome. :)
#
# $Id$
#

SNMPDUMP=../src/snmpdump

test_pcap_reader_xml_writer()
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

test_pcap_reader_csv_writer()
{
    for file in *.pcap; do
	$SNMPDUMP -i pcap -o csv $file \
	    | diff -u `basename $file .pcap`.csv -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_xml_reader_xml_writer()
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

test_xml_reader_csv_writer()
{
    for file in *.xml; do
	$SNMPDUMP -i xml -o csv $file \
	    | diff -u `basename $file .xml`.csv -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_csv_reader_xml_writer()
{
    echo "CSV contains less information than XML, so testing"
    echo "CSV reader -> XML writer does not make much sense - skipping tests"
    return
    for file in *.csv; do
	$SNMPDUMP -i csv -o xml $file \
	    | xmllint --format - \
	    | diff -u `basename $file .csv`.xml -
	if [ $? == 0 ]; then
            echo "$FUNCNAME: $file: PASSED"
        else
            echo "$FUNCNAME: $file: FAILED"
        fi
    done
}

test_csv_reader_csv_writer()
{
    for file in *.csv; do
	$SNMPDUMP -i csv -o csv $file \
	    | diff -u $file -
	if [ $? == 0 ]; then
            echo "$FUNCNAME: $file: PASSED"
        else
            echo "$FUNCNAME: $file: FAILED"
        fi
    done
}

test_pcap_reader_xml_writer
echo ""
test_pcap_reader_csv_writer
echo ""
test_xml_reader_xml_writer
echo ""
test_xml_reader_csv_writer
echo ""
test_csv_reader_xml_writer
echo ""
test_csv_reader_csv_writer
echo ""

