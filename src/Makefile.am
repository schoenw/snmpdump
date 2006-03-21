INCLUDES		= -I../libanon $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS) $(NIDSINC)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= snmpdump snmpanon

snmpdump_SOURCES	= snmpdump.c \
			  pcap-read.c \
			  xml-read.c xml-write.c \
			  csv-write.c \
			  filter.c
snmpdump_LDADD		= $(NIDSLIB) -lpcap $(XML_LIBS)

snmpanon_SOURCES	= snmpanon.c xpath-filter.c
snmpanon_LDADD		= ../libanon/libanon.la $(XML_LIBS) $(OPENSSL_LIBS) -lsmi

man_MANS		= snmpdump.1
