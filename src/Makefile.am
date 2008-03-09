INCLUDES		= $(LIBANON_CFLAGS) $(XML_CFLAGS) $(XML_CPPFLAGS) \
			  $(OPENSSL_CFLAGS) $(NIDSINC)

EXTRA_DIST		= snmp.h anon.h \
			  scanner.l parser.y \
			  $(man_MANS)

bin_PROGRAMS		= snmpdump

snmpdump_SOURCES	= snmpdump.c \
			  pcap-read.c \
			  xml-read.c xml-write.c \
			  csv-read.c csv-write.c \
			  filter.c \
			  anon.c \
			  snmp.c \
			  flow.c \
			  scanner.c \
			  parser.c
snmpdump_LDADD		= $(LIBANON_LIBS) $(OPENSSL_LIBS) \
			  $(NIDSLIB) -lpcap $(XML_LIBS) -ll

man_MANS		= snmpdump.1

scanner.c: scanner.l parser.h
	flex --debug -o scanner.c scanner.l

parser.c parser.h: parser.y
	bison --debug -o parser.c -d parser.y
