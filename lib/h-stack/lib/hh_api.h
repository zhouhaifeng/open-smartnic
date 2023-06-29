#ifndef _HSTACK_API_H
#define _HSTACK_API_H

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "hh_event.h"
#include "hh_errno.h"

struct linux_sockaddr {
    short sa_family;
    char sa_data[14];
};

#define AF_INET6_LINUX    10
#define PF_INET6_LINUX    AF_INET6_LINUX
#define AF_INET6_FREEBSD    28
#define PF_INET6_FREEBSD    AF_INET6_FREEBSD

typedef int (*loop_func_t)(void *arg);

int hh_init(int argc, char * const argv[]);

void hh_run(loop_func_t loop, void *arg);

/* POSIX-LIKE api begin */

int hh_fcntl(int fd, int cmd, ...);

int hh_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int hh_ioctl(int fd, unsigned long request, ...);

int hh_socket(int domain, int type, int protocol);

int hh_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int hh_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int hh_listen(int s, int backlog);
int hh_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int hh_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int hh_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int hh_close(int fd);
int hh_shutdown(int s, int how);

int hh_getpeername(int s, struct linux_sockaddr *name,
    socklen_t *namelen);
int hh_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen);

ssize_t hh_read(int d, void *buf, size_t nbytes);
ssize_t hh_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t hh_write(int fd, const void *buf, size_t nbytes);
ssize_t hh_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t hh_send(int s, const void *buf, size_t len, int flags);
ssize_t hh_sendto(int s, const void *buf, size_t len, int flags,
    const struct linux_sockaddr *to, socklen_t tolen);
ssize_t hh_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t hh_recv(int s, void *buf, size_t len, int flags);
ssize_t hh_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t hh_recvmsg(int s, struct msghdr *msg, int flags);

int hh_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);

int hh_poll(struct pollfd fds[], nfds_t nfds, int timeout);

int hh_kqueue(void);
int hh_kevent(int kq, const struct kevent *changelist, int nchanges, 
    struct kevent *eventlist, int nevents, const struct timespec *timeout);
int hh_kevent_do_each(int kq, const struct kevent *changelist, int nchanges, 
    void *eventlist, int nevents, const struct timespec *timeout, 
    void (*do_each)(void **, struct kevent *));

int hh_gettimeofday(struct timeval *tv, struct timezone *tz);

int hh_dup(int oldfd);
int hh_dup2(int oldfd, int newfd);

/* POSIX-LIKE api end */


#ifdef __cplusplus
}
#endif
#endif

