#ifndef _HH_EPOLL_H
#define _HH_EPOLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/epoll.h>

int hh_epoll_create(int size);
int hh_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int hh_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif