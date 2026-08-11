/* Compatibility symbols used by current Rust std/Tokio but absent from the
 * Android 2.3 bionic exports. Linux 2.6 already provides the corresponding
 * syscalls; the small wrappers keep the library loadable on API 9/10. */
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <malloc.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC O_CLOEXEC
#endif

int epoll_create1(int flags) {
    int fd;
    if (flags & ~EPOLL_CLOEXEC) {
        errno = EINVAL;
        return -1;
    }
    fd = (int)syscall(__NR_epoll_create1, flags);
    if (fd >= 0 || errno != ENOSYS) return fd;
    fd = epoll_create(1);
    if (fd >= 0 && (flags & EPOLL_CLOEXEC) && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int ftruncate64(int fd, off64_t length) {
    uint64_t value = (uint64_t)length;
    return (int)syscall(__NR_ftruncate64, fd, 0,
                       (uint32_t)value, (uint32_t)(value >> 32));
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return open(path, flags, mode);
}

int openat64(int directory, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return (int)syscall(__NR_openat, directory, path, flags, mode);
}

ssize_t pread64(int fd, void *buffer, size_t count, off64_t offset) {
    uint64_t value = (uint64_t)offset;
    return (ssize_t)syscall(__NR_pread64, fd, buffer, count, 0,
                            (uint32_t)value, (uint32_t)(value >> 32));
}

ssize_t pwrite64(int fd, const void *buffer, size_t count, off64_t offset) {
    uint64_t value = (uint64_t)offset;
    return (ssize_t)syscall(__NR_pwrite64, fd, buffer, count, 0,
                            (uint32_t)value, (uint32_t)(value >> 32));
}

int sched_getaffinity(pid_t pid, size_t size, void *mask) {
    return (int)syscall(__NR_sched_getaffinity, pid, size, mask);
}

int posix_memalign(void **result, size_t alignment, size_t size) {
    void *allocation;
    if (alignment < sizeof(void *) || (alignment & (alignment - 1)) != 0) return EINVAL;
    allocation = memalign(alignment, size);
    if (allocation == NULL) return ENOMEM;
    *result = allocation;
    return 0;
}

int mst5_mkfifo(const char *path, mode_t mode) __asm__("mkfifo");
int mst5_mkfifo(const char *path, mode_t mode) {
    return mknod(path, mode | S_IFIFO, 0);
}

typedef void (*mst5_signal_handler)(int);
mst5_signal_handler mst5_signal(int number, mst5_signal_handler handler) __asm__("signal");
mst5_signal_handler mst5_signal(int number, mst5_signal_handler handler) {
    struct sigaction action;
    struct sigaction previous;
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    if (sigaction(number, &action, &previous) < 0) return SIG_ERR;
    return previous.sa_handler;
}

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
    (void)callback;
    (void)data;
    return 0;
}
