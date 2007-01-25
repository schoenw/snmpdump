EXTRA_DIST		= snmptrace.rnc

test: snmptrace.rng snmptrace.xsd

measure.txt:	measure.xml snmptrace.rnc
	xml2rfc measure.xml

snmptrace.rng: snmptrace.rnc
	trang $< $@

snmptrace.xsd: snmptrace.rnc
	trang $< $@
