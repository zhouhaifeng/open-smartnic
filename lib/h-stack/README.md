
1. high performance network library
2. ported freebsd 11.01 network stack into userspace
3. using ring/mmap/epoll without dpdk
4. multiple threads and multiple cores

referance:
1. epoll
[epoll](https://man7.org/linux/man-pages/man7/epoll.7.html)
2. io_uring
[io_uring-only sendmsg + recvmsg zerocopy](https://lore.kernel.org/io-uring/acc66238-0d27-cd22-dac4-928777a8efbc@gmail.com/T/#m7e2356589fda377861c16abfb443b125cde4d151)
3. uio
4. virtio
5. vfio
6. vdpa
7. dpdk
8. fstack
9. mtcp
10. seastar