#!/bin/sh

# reads IPv4 addresses from standard input (one address per line)
# and outputs them sorted to standard output

sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 $1

#awk '{gsub("\\."," "); print };' | sort -n | \
#		awk '{gsub(" ","."); print };'

