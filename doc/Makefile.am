EXTRA_DIST		= snmptrace.rnc

measure.txt:	measure.xml snmptrace.rnc
	expand snmpstat.pl | sed -e 's/</\&lt;/g' -e 's/>/\&gt;/g' > snmpstat.pl.xml
	xml2rfc measure.xml
