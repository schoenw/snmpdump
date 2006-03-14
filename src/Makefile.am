INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS) $(NIDSINC)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= snmpdump snmpanon anon

snmpdump_SOURCES	= snmpdump.c \
			  pcap-read.c \
			  xml-read.c xml-write.c \
			  csv-write.c # xpath-filter.c
snmpdump_LDADD		= $(NIDSLIB) -lpcap $(XML_LIBS)

snmpanon_SOURCES	= snmpanon.c xpath-filter.c
snmpanon_LDADD		= libanon.la $(XML_LIBS) $(OPENSSL_LIBS) -lsmi

anon_SOURCES		= anon.c
anon_LDADD		= libanon.la $(OPENSSL_LIBS)

man_MANS		= snmpdump.1 anon.1 anon-ip.3

include_HEADERS		= libanon.h
lib_LTLIBRARIES		= libanon.la
libanon_la_SOURCES	= anon-ip.c anon-ipv6.c anon-mac.c anon-int64.c anon-uint64.c anon-octet-string.c
libanon_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@
