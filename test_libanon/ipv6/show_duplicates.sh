#!/bin/sh

# reads IPv6 addresses from standard input (one address per line)
# and outputs all duplicate lines.
#
# to get each duplicate line only once, use uniq -d instead of uniq -D

./hex2dec | sort | uniq -D | ./dec2hex  

#sort -n -t : -k 1,1 -k 2,2 -k 3,3 -k 4,4 -k 5,5 -k 6,6 $1

