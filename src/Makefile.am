INCLUDES		= $(XML_CFLAGS) $(XML_CPPFLAGS)

EXTRA_DIST		= $(man_MANS)

bin_PROGRAMS		= snmpdump

snmpdump_SOURCES	= snmpdump.c
snmpdump_LDADD		= $(XML_LIBS) -lnids -lpcap

man_MANS		= snmpdump.1
