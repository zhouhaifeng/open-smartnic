#ifndef _HH_EPOLL_H
#define _HH_EPOLL_H

#ifdef __cplusplus
extern "C" {
#endif

void hh_init()
{
    //load config
    
    //dma
    /* NIC is smart enough and can locate the end (userspace) buffer and
    DMA there directly. That requires parsing TCP/UDP headers, etc., or
    having a more versatile API like infiniband. + extra NIC features.*/

    //if up
}

#ifdef __cplusplus
}
#endif

#endif