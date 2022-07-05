#ifndef _C_ZIG_INTEROP
#define _C_ZIG_INTEROP

// Returns the file descriptor of the device. Will overwrite `dev_name` with the actual final
// device name.
int tun_alloc(char *dev_name);

#endif
