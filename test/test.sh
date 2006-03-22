#!/bin/sh
#
# script for testing the xml-read.c module
#
# the idea is that reading xml and then writing xml
#  should have output the same as input
#

for file in `ls *.xml `; do
	../src/snmpdump -i xml -o xml $file \
		| xmllint --format - \
		| diff -u $file -
	if [ $? == 0 ]; then
		echo "$file: PASSED"
	else
		echo "$file: FAILED"
	fi
done
