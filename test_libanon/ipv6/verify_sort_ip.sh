#!/bin/sh

# reads IPv4 addresses from standard input (one address per line)
# and checks if the  are sorted

./hex2dec | sort -c | ./dec2hex

