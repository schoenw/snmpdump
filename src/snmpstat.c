/*
 * snmpstat.c --
 *
 * A simple C program to analyze SNMP traffic traces using the libxml
 * xml reader interface. This is a fast memory conserving version of
 * the perl scripts.
 *
 * (c) 2006 Juergen Schoenwaelder <j.schoenwaelder@iu-bremen.de>
 */

#include <config.h>

#include <libxml/xmlreader.h>

static const char *progname = "snmpdump";

static enum {
	IN_NONE,
	IN_SNMPTRACE,
	IN_PACKET,
	IN_SNMP,
	IN_VERSION,
	IN_COMMUNITY,
	/* add SNMPv3 stuff here */
	IN_TRAP,
	IN_ENTERPRISE,
	IN_AGENT_ADDR,
	IN_GENERIC_TRAP,
	IN_SPECIFIC_TRAP,
	IN_TIME_STAMP,
	IN_VARIABLE_BINDINGS,
	IN_GET_REQUEST,
	IN_GET_NEXT_REQUEST,
	IN_GET_BULK_REQUEST,
	IN_SET_REQUEST,
	IN_INFORM,
	IN_TRAP2,
	IN_RESPONSE,
	IN_REPORT,
	IN_REQUEST_ID,
	IN_ERROR_STATUS,
	IN_ERROR_INDEX,
	IN_VARBIND,
	IN_NAME,
	IN_NULL,
	IN_integer32,
	IN_UNSIGNED32,
	IN_UNSIGNED64,
	IN_IPADDRESS,
	IN_OCTET_STRING,
	IN_OBJECT_IDENTIFIER,
	IN_NO_SUCH_OBJECT,
	IN_NO_SUCH_INSTANCE,
	IN_END_OF_MIB_VIEW
} state = IN_NONE;

static int version[3];
static int total;

static void
process_node(xmlTextReaderPtr reader)
{
    xmlChar *name, *value;
    long int num;
    char *end;
	
    if (state == IN_VERSION) {
	value = xmlTextReaderValue(reader);
	if (value) {
	    num = strtol((char *) value, &end, 10);
	    if (*end == '\0' && num >=0 && num <3) {
		version[num]++;
		total++;
	    }
	}
	xmlFree(value);
    }

    name = xmlTextReaderName(reader);
    if (name && xmlStrcmp(name, BAD_CAST("version")) == 0) {
	state = IN_VERSION;
    } else {
	state = IN_NONE;
    }

    xmlFree(name);
}

static int
stream_file(char *filename)
{
    xmlTextReaderPtr reader;
    int i, ret;
    
    if (filename) {
	reader = xmlNewTextReaderFilename(filename);
	if (! reader) {
	    return -1;
	}
    } else {
	xmlParserInputBufferPtr input;
	
	input = xmlParserInputBufferCreateFile(stdin,
		       XML_CHAR_ENCODING_NONE);
	if (! input) {
	    return -1;
	}
	reader = xmlNewTextReader(input, NULL);
	if (! reader) {
	    xmlFreeParserInputBuffer(input);
	    return -1;
	}
    }
    
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	process_node(reader);
	ret = xmlTextReaderRead(reader);
    }
    xmlFreeTextReader(reader);
    if (ret != 0) {
	fprintf(stderr, "%s: xmlTextReaderRead: failed to parse '%s'\n",
		progname, filename);
	return -2;
    }

    printf("SNMP version statistics:\n\n");
    for (i = 0; i < 3; i++) {
	printf("%18d: %5d  %3d%%\n", i, version[i],
	       total ? 100*version[i]/total : 0);
    }
    printf("    ---------------------------\n");
    printf("%18s: %5d  %3d%%\n\n", "total", total, 100);

    return 0;
}

int
main(int argc, char **argv)
{
    int i;

    if (argc == 1) {
	stream_file(NULL);
    } else {
	for (i = 1; i < argc; i++) {
	    stream_file(argv[i]);
	}
    }
    
    return 0;
}
