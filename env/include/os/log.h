#pragma once

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#include <stdint.h>

#if DEBUG_LEVEL > 0
// No pre/postconditions, this method needs not be verified
void os_debug(const char *message);
void os_debug_hex(uint64_t num);
#else
static inline void os_debug(const char *message)
//@ requires emp;
//@ ensures emp;
//@ terminates;
{
	(void)message;
	// Nothing. Ensure the message can be removed from the final binary.
}

void os_debug_hex(uint64_t num)
{
	(void)num;
}
#endif
