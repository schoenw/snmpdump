#!/bin/sh

# reads IPv6 addresses from standard input (one address per line)
# and outputs them sorted to standard output. Duplicates are removed.

./hex2dec | sort | uniq | ./dec2hex  

#sort -n -t : -k 1,1 -k 2,2 -k 3,3 -k 4,4 -k 5,5 -k 6,6 $1

