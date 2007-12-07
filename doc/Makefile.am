EXTRA_DIST		= snmptrace.rnc snmptrace.rng snmptrace.xsd

test: snmptrace.rng snmptrace.xsd

measure.txt:	measure.xml snmptrace.rnc
	xml2rfc measure.xml

definitions.txt: definitions.xml
	xml2rfc definitions.xml

snmptrace.rng: snmptrace.rnc
	trang $< $@

snmptrace.xsd: snmptrace.rnc
	trang $< $@
