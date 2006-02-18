INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS) $(NIDSINC)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= snmpdump snmpanon snmpstat anon

snmpdump_SOURCES	= snmpdump.c # xpath-filter.c
snmpdump_LDADD		= $(NIDSLIB) -lpcap

snmpanon_SOURCES	= snmpanon.c xpath-filter.c
snmpanon_LDADD		= libanon.la $(XML_LIBS) $(OPENSSL_LIBS) -lsmi

snmpstat_SOURCES	= snmpstat.c
snmpstat_LDADD		= $(XML_LIBS)

anon_SOURCES		= anon.c
anon_LDADD		= libanon.la $(OPENSSL_LIBS)

man_MANS		= snmpdump.1 anon.1 anon-ip.3

include_HEADERS		= libanon.h
lib_LTLIBRARIES		= libanon.la
libanon_la_SOURCES	= anon-ip.c anon-ipv6.c anon-mac.c anon-int64.c anon-uint64.c anon-octet-string.c
libanon_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@
