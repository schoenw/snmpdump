#!/bin/sh

# generates N random IPv4 addresses and writes them to standard output
# N is first argument

N=$1

for ((i=0; $i<$N; i++ )); do
	echo -n $(($RANDOM % 256 )).
	echo -n $(($RANDOM % 256 )).
	echo -n $(($RANDOM % 256 )).
	echo $(($RANDOM % 256 ))
done

