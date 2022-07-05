#ifndef _C_ZIG_INTEROP
#define _C_ZIG_INTEROP

// Header file that helps a bit translating c into zig

#define STRINGIFY_IMPL(val) #val
#define STRIGIFY(val) STRINGIFY_IMPL(val)

#include <linux/if.h>

#define ZIG_ifr_flags STRINGIFY(ifr_flags)

#endif
