#include "os/log.h"


#if DEBUG_LEVEL > 0
#include <stdio.h>

void os_debug(const char* message)
{
	fprintf(stderr, "%s\n", message);
	fflush(stderr);
}

void os_debug_hex(uint64_t num)
{
	fprintf(stderr, "%lx\n", num);
	fflush(stderr);
}
#endif
