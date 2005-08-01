INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS) $(OPENSSL_CFLAGS)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= snmpdump anon

snmpdump_SOURCES	= snmpdump.c
snmpdump_LDADD		= libanon.la $(XML_LIBS) $(OPENSSL_LIBS) -lnids -lnet -lpcap

anon_SOURCES		= anon.c
anon_LDADD		= libanon.la $(OPENSSL_LIBS)

man_MANS		= snmpdump.1 anon.1

include_HEADERS		= libanon.h
lib_LTLIBRARIES		= libanon.la
libanon_la_SOURCES	= anon-ip.c anon-mac.c
libanon_la_LDFLAGS	= -version-info @VERSION_LIBTOOL@
