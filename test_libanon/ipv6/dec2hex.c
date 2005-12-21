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
dec2hex(FILE *f)
{
    struct in6_addr addr;
    char buf[10*INET6_ADDRSTRLEN];
    int done = 0;
    int i;
    
    while (!done) {
	for(i=0;i<16;i++) {
	    if (1 != fscanf(f,"%3d:", &(addr.s6_addr[i]))) {
		done = 1;
		break;
	    }
	}
	if (done) {
	    break;
	}
	printf("%s\n", inet_ntop(AF_INET6, &addr, buf, sizeof(buf)));
    }
}

int main(int argc, char **argv) {
    FILE *in;
    dec2hex(stdin);
}
