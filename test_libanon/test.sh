#!/bin/bash
#
# Shell script for regression testing libanon.
#
# $Id$
#

ANON=../libanon/anon
PASSPHRASE=testing

test_ipv4_pref()
{
    for file in ipv4.*.in; do
	$ANON ipv4 -p $PASSPHRASE $file \
	    | diff -u `basename $file .in`.out -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_ipv4_pref_lex()
{
    for file in ipv4.*.in; do
	$ANON ipv4 -p $PASSPHRASE -l $file \
	    | diff -u `basename $file .in`.out.lex -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_ipv6_pref()
{
    for file in ipv6.*.in; do
	$ANON ipv6 -p $PASSPHRASE $file \
	    | diff -u `basename $file .in`.out -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_ipv6_pref_lex()
{
    for file in ipv6.*.in; do
	$ANON ipv6 -p $PASSPHRASE -l $file \
	    | diff -u `basename $file .in`.out.lex -
	if [ $? == 0 ]; then
	    echo "$FUNCNAME: $file: PASSED"
	else 
	    echo "$FUNCNAME: $file: FAILED"
	fi
    done
}

test_ipv4_pref
echo ""
test_ipv4_pref_lex
echo ""
test_ipv6_pref
echo ""
test_ipv6_pref_lex
echo ""
