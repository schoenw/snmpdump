PCAP_FILES		= frags.pcap misc.pcap scli.pcap traps.pcap

EXTRA_DIST		= $(PCAP_FILES)

SNMPDUMP		= ../src/snmpdump

SUFFIXES = .pcap .xml .csv

.pcap.xml:
	$(SNMPDUMP) -o xml $< | xmllint --format - > $@

.pcap.csv:
	$(SNMPDUMP) -o csv $< > $@

convert: $(PCAP_FILES:.pcap=.csv) $(PCAP_FILES:.pcap=.xml)

validate:
	for f in $(PCAP_FILES:.pcap=.xml) ; do \
		xmllint --relaxng ../doc/snmptrace.rng $$f > /dev/null; \
	done
