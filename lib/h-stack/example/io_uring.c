#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "liburing.h"

#define MAX_PKT_SIZE    1500
#define MAX_PKT_COUNT   10


static void submit_recv(struct io_uring *ring, int sockfd, void *data)
{
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe)
                return;

        io_uring_prep_recv(sqe, sockfd, data, MAX_PKT_SIZE, 0);
        io_uring_sqe_set_data(sqe, data);
}

static void submit_all_recv(struct io_uring *ring, int sockfd)
{
        struct io_uring_sqe *sqe;
        void *data;

    	//获取空闲的sqe
        while ((sqe = io_uring_get_sqe(ring))) {
                data = malloc(MAX_PKT_SIZE);
            	//将sqe初始化为recv操作
                io_uring_prep_recv(sqe, sockfd, data, MAX_PKT_SIZE, 0);
            	//设置sqe的私有数据，方便我们在操作完成后获取到其中的报文数据
                io_uring_sqe_set_data(sqe, data);
        }
}

static int do_recv(struct io_uring *ring, int sockfd)
{
        struct io_uring_cqe *cqe;
        void *data;
        int count;

    	//对提交数组中所有空闲的提交实体进行初始化，并放到提交队列
        submit_all_recv(ring, sockfd);
    	//将提交队列中的请求提交给内核处理
        io_uring_submit(ring);
        count = 0;

        while (true) {
            	//从完成队列中取出一个实例，返回非0的话代表完成队列中没有可取实例
                if (io_uring_peek_cqe(ring, &cqe)) {
                    	//进行一次提交操作，将提交队列中的请求批量提交给内核处理
                        io_uring_submit(ring);
                    	//以阻塞的方式等待完成队列中存在可用实例
                        io_uring_wait_cqe(ring, &cqe);
                }
                if (!cqe) {
                        fprintf(stderr, "io_uring_get_sqe failed\n");
                        continue;
                }
            	//获取完成实例中之前设置的私有数据
                data = io_uring_cqe_get_data(cqe);
                count++;
                if (!(count % 1000))
                        printf("recved packet count: %d, queue len:%d\n", count, io_uring_sq_ready(ring));
				//将完成实例标识为“完成处理”，其对应的提交实例可以被使用了
                io_uring_cqe_seen(ring, cqe);
            	//继续进行请求的提交。这里使用之前分配好的data，避免重复的内存分配
                submit_recv(ring, sockfd, data);
        }

        return 0;
}

int main()
{
        struct sockaddr_in saddr;
        struct io_uring ring;
        int ret, sockfd;

    	//初始化uring，设置提交队列长度为10
        ret = io_uring_queue_init(10, &ring, 0);
        if (ret < 0)
        {
                perror("queue_init");
                goto err;
        }

    	//初始化UDP套接字
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons(8080);
        sockfd = hh_socket(AF_INET, SOCK_DGRAM, 0);
        ret = hh_bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
        if (ret < 0)
        {
                perror("bind");
                goto err;
        }
    
    	//开始报文接收
        do_recv(&ring, sockfd);
err:
        return -1;
}