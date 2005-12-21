#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*
 * Trim a string be removing leading or trailing white space
 * characters.
 */

static int
trim(char *buffer)
{
    char *s, *e;

    if (! buffer) return 0;

    for (s = buffer; *s && isspace(*s); s++) ;

    for (e = s + strlen(s)-1; e > s && isspace(*e); e--) *e = 0;
    
    memmove(buffer, s, e-s+2);
    return 1;
}

void
hex2dec(FILE *f)
{
    struct in6_addr addr;
    char buf[10*INET6_ADDRSTRLEN];
    int i;

    while (fgets(buf, sizeof(buf), f) 
	   && trim(buf)
	   && inet_pton(AF_INET6, buf, &addr) > 0) {
	for(i=0;i<16;i++) {
	    printf("%03d:", addr.s6_addr[i]);
	}
	printf("\n");
    }
    //printf("%s\n", inet_ntop(AF_INET6, &addr, buf, sizeof(buf)));
}

int main(int argc, char **argv) {
    FILE *in;
    hex2dec(stdin);
}
