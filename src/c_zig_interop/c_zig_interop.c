#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define print_error(...) _print_error(__VA_ARGS__, __FILE__, __func__, __LINE__);
#define print_errno(...) _print_errno(__VA_ARGS__, __FILE__, __func__, __LINE__);

void _print_error(const char* message, const char* fname, const char* fn_name, int line) {
    fprintf(stderr, "Error: %s (at %s:%s:%d)\n", message, fname, fn_name, line);
}

void _print_errno(const char* message, const char* fname, const char* fn_name, int line) {
    fprintf(stderr, "Error (%s): %s (at %s:%s:%d)\n",
            strerror(errno), message, fname, fn_name, line);
}

int tun_alloc_with_flags(char *dev_name, int flags) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", flags);
    if (fd < 0) {
        print_errno("failed opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof ifr);

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (dev_name[0]) strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    int ret = ioctl(fd, TUNSETIFF, (void*)&ifr);

    if (ret < 0) {
        print_errno("ioctl failed");
        close(fd);
        return ret;
    }

    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

int tun_alloc(char *dev_name) {
    return tun_alloc_with_flags(dev_name, O_RDWR);
}

int tun_alloc_nonblock(char *dev_name) {
    return tun_alloc_with_flags(dev_name, O_RDWR | O_NONBLOCK);
}
