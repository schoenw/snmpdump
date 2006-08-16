INCLUDES		= -I../libanon $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS) $(NIDSINC)

EXTRA_DIST		= snmp.h anon.h \
			  $(man_MANS)

bin_PROGRAMS		= snmpdump

snmpdump_SOURCES	= snmpdump.c \
			  pcap-read.c \
			  xml-read.c xml-write.c \
			  csv-read.c csv-write.c \
			  filter.c \
			  anon.c \
			  snmp.c \
			  flow.c
snmpdump_LDADD		= ../libanon/libanon.la $(OPENSSL_LIBS) \
			  $(NIDSLIB) -lpcap $(XML_LIBS)

man_MANS		= snmpdump.1
