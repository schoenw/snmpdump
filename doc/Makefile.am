EXTRA_DIST		= snmptrace.rnc

measure.txt:	measure.xml snmptrace.rnc
	xml2rfc measure.xml

snmptrace.rng: snmptrace.rnc
	trang $< > $@

snmptrace.xsd: snmptrace.rnc
	trang $< > $@
