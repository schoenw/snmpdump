#!/bin/sh

# generates N random IPv6 addresses and writes them to standard output
# N is first argument

N=$1

for ((i=0; $i<$N; i++ )); do
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x:" $(($RANDOM % 65536 ))
	printf "%x\n" $(($RANDOM % 65536 ))
done

