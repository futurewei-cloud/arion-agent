//
// Created by user on 12/16/22.
//

// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2022 Intel Corporation. */

#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <err.h>
//#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

//#include <xdp/libxdp.h>
#include <xsk.h>
//#include <xdp/xsk.h>
#include <af_xdp_user_multi_thread.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "util.h"
#include "xdp/trn_datamodel.h"
#include <db_client.h>
#include <bpf_endian.h>


#define VXL_DSTPORT 0xb512 // UDP dport 4789(0x12b5) for VxLAN overlay
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

struct arp_message {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((__packed__));

struct vxlanhdr_internal {
    /* Big endian! */
    __u8 rsvd1 : 3;
    __u8 i_flag : 1;
    __u8 rsvd2 : 4;
    __u8 rsvd3[3];
    __u8 vni[3];
    __u8 rsvd4;
};

/* This program illustrates the packet forwarding between multiple AF_XDP
 * sockets in multi-threaded environment. All threads are sharing a common
 * buffer pool, with each socket having its own private buffer cache.
 *
 * Example 1: Single thread handling two sockets. The packets received by socket
 * A (interface IFA, queue QA) are forwarded to socket B (interface IFB, queue
 * QB), while the packets received by socket B are forwarded to socket A. The
 * thread is running on CPU core X:
 *
 *         ./xsk_fwd -i IFA -q QA -i IFB -q QB -c X
 *
 * Example 2: Two threads, each handling two sockets. The thread running on CPU
 * core X forwards all the packets received by socket A to socket B, and all the
 * packets received by socket B to socket A. The thread running on CPU core Y is
 * performing the same packet forwarding between sockets C and D:
 *
 *         ./xsk_fwd -i IFA -q QA -i IFB -q QB -i IFC -q QC -i IFD -q QD
 *         -c CX -c CY
 */

/*
 * Buffer pool and buffer cache
 *
 * For packet forwarding, the packet buffers are typically allocated from the
 * pool for packet reception and freed back to the pool for further reuse once
 * the packet transmission is completed.
 *
 * The buffer pool is shared between multiple threads. In order to minimize the
 * access latency to the shared buffer pool, each thread creates one (or
 * several) buffer caches, which, unlike the buffer pool, are private to the
 * thread that creates them and therefore cannot be shared with other threads.
 * The access to the shared pool is only needed either (A) when the cache gets
 * empty due to repeated buffer allocations and it needs to be replenished from
 * the pool, or (B) when the cache gets full due to repeated buffer free and it
 * needs to be flushed back to the pull.
 *
 * In a packet forwarding system, a packet received on any input port can
 * potentially be transmitted on any output port, depending on the forwarding
 * configuration. For AF_XDP sockets, for this to work with zero-copy of the
 * packet buffers when, it is required that the buffer pool memory fits into the
 * UMEM area shared by all the sockets.
 */

struct bpool_params {
    u32 n_buffers;
    u32 buffer_size;
    int mmap_flags;

    u32 n_users_max;
    u32 n_buffers_per_slab;
};

/* This buffer pool implementation organizes the buffers into equally sized
 * slabs of *n_buffers_per_slab*. Initially, there are *n_slabs* slabs in the
 * pool that are completely filled with buffer pointers (full slabs).
 *
 * Each buffer cache has a slab for buffer allocation and a slab for buffer
 * free, with both of these slabs initially empty. When the cache's allocation
 * slab goes empty, it is swapped with one of the available full slabs from the
 * pool, if any is available. When the cache's free slab goes full, it is
 * swapped for one of the empty slabs from the pool, which is guaranteed to
 * succeed.
 *
 * Partially filled slabs never get traded between the cache and the pool
 * (except when the cache itself is destroyed), which enables fast operation
 * through pointer swapping.
 */
struct bpool {
    struct bpool_params params;
    pthread_mutex_t lock;
    void *addr;

    u64 **slabs;
    u64 **slabs_reserved;
    u64 *buffers;
    u64 *buffers_reserved;

    u64 n_slabs;
    u64 n_slabs_reserved;
    u64 n_buffers;

    u64 n_slabs_available;
    u64 n_slabs_reserved_available;

    struct xsk_umem_config umem_cfg;
    struct xsk_ring_prod umem_fq;
    struct xsk_ring_cons umem_cq;
    struct xsk_umem *umem;
};

static bool xsk_page_aligned(void *buffer)
{
    unsigned long addr = (unsigned long)buffer;

    return !(addr & (getpagesize() - 1));
}

static struct bpool *
bpool_init(struct bpool_params *params,
           struct xsk_umem_config *umem_cfg)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    u64 n_slabs, n_slabs_reserved, n_buffers, n_buffers_reserved;
    u64 slabs_size, slabs_reserved_size;
    u64 buffers_size, buffers_reserved_size;
    u64 total_size, i;
    struct bpool *bp;
    u8 *p;
    int status;

    /* mmap prep. */
    if (setrlimit(RLIMIT_MEMLOCK, &r))
        return NULL;

    /* bpool internals dimensioning. */
    n_slabs = (params->n_buffers + params->n_buffers_per_slab - 1) /
              params->n_buffers_per_slab;
    printf("bpool_init: n_slabs = %ld\n", n_slabs);
    n_slabs_reserved = params->n_users_max * 2;
    n_buffers = n_slabs * params->n_buffers_per_slab;
    n_buffers_reserved = n_slabs_reserved * params->n_buffers_per_slab;

    slabs_size = n_slabs * sizeof(u64 *);
    slabs_reserved_size = n_slabs_reserved * sizeof(u64 *);
    buffers_size = n_buffers * sizeof(u64);
    buffers_reserved_size = n_buffers_reserved * sizeof(u64);

    total_size = sizeof(struct bpool) +
                 slabs_size + slabs_reserved_size +
                 buffers_size + buffers_reserved_size;

    /* bpool memory allocation. */
    p = static_cast<u8 *>(calloc(total_size, sizeof(u8)));
    if (!p)
        return NULL;

    /* bpool memory initialization. */
    bp = (struct bpool *)p;
    memcpy(&bp->params, params, sizeof(*params));
    bp->params.n_buffers = n_buffers;

    bp->slabs = (u64 **)&p[sizeof(struct bpool)];
    bp->slabs_reserved = (u64 **)&p[sizeof(struct bpool) +
                                    slabs_size];
    bp->buffers = (u64 *)&p[sizeof(struct bpool) +
                            slabs_size + slabs_reserved_size];
    bp->buffers_reserved = (u64 *)&p[sizeof(struct bpool) +
                                     slabs_size + slabs_reserved_size + buffers_size];

    bp->n_slabs = n_slabs;
    bp->n_slabs_reserved = n_slabs_reserved;
    bp->n_buffers = n_buffers;

    for (i = 0; i < n_slabs; i++)
        bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
    bp->n_slabs_available = n_slabs;

    for (i = 0; i < n_slabs_reserved; i++)
        bp->slabs_reserved[i] = &bp->buffers_reserved[i *
                                                      params->n_buffers_per_slab];
    bp->n_slabs_reserved_available = n_slabs_reserved;

    for (i = 0; i < n_buffers; i++)
        bp->buffers[i] = i * params->buffer_size;

    /* lock. */
    status = pthread_mutex_init(&bp->lock, NULL);
    if (status) {
        free(p);
        return NULL;
    }

    /* mmap. */
    bp->addr = mmap(NULL,
                    n_buffers * params->buffer_size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
                    -1,
                    0);
    if (bp->addr == MAP_FAILED) {
        pthread_mutex_destroy(&bp->lock);
        free(p);
        return NULL;
    }

    printf("xsk_umem__create: size: %ld, xsk_page_aligned: %b\n",
           bp->params.n_buffers * bp->params.buffer_size, xsk_page_aligned(bp->addr));
    /* umem. */
    status = xsk_umem__create(&bp->umem,
                              bp->addr,
                              bp->params.n_buffers * bp->params.buffer_size,
                              &bp->umem_fq,
                              &bp->umem_cq,
                              umem_cfg);
    if (status) {
        printf("xsk_umem__create failed with status: %d\n", status);
        munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
        pthread_mutex_destroy(&bp->lock);
        free(p);
        return NULL;
    }
    memcpy(&bp->umem_cfg, umem_cfg, sizeof(*umem_cfg));

    return bp;
}

static void
bpool_free(struct bpool *bp)
{
    if (!bp)
        return;

    xsk_umem__delete(bp->umem);
    munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
    pthread_mutex_destroy(&bp->lock);
    free(bp);
}

struct bcache {
    struct bpool *bp;

    u64 *slab_cons;
    u64 *slab_prod;

    u64 n_buffers_cons;
    u64 n_buffers_prod;
};

static u32
bcache_slab_size(struct bcache *bc)
{
    struct bpool *bp = bc->bp;

    return bp->params.n_buffers_per_slab;
}

static struct bcache *
bcache_init(struct bpool *bp)
{
    struct bcache *bc;

    bc = static_cast<bcache *>(calloc(1, sizeof(struct bcache)));
    if (!bc)
        return NULL;

    bc->bp = bp;
    bc->n_buffers_cons = 0;
    bc->n_buffers_prod = 0;

    pthread_mutex_lock(&bp->lock);
    if (bp->n_slabs_reserved_available == 0) {
        pthread_mutex_unlock(&bp->lock);
        free(bc);
        return NULL;
    }

    bc->slab_cons = bp->slabs_reserved[bp->n_slabs_reserved_available - 1];
    bc->slab_prod = bp->slabs_reserved[bp->n_slabs_reserved_available - 2];
    bp->n_slabs_reserved_available -= 2;
    pthread_mutex_unlock(&bp->lock);

    return bc;
}

static void
bcache_free(struct bcache *bc)
{
    struct bpool *bp;

    if (!bc)
        return;

    /* In order to keep this example simple, the case of freeing any
	 * existing buffers from the cache back to the pool is ignored.
	 */

    bp = bc->bp;
    pthread_mutex_lock(&bp->lock);
    bp->slabs_reserved[bp->n_slabs_reserved_available] = bc->slab_prod;
    bp->slabs_reserved[bp->n_slabs_reserved_available + 1] = bc->slab_cons;
    bp->n_slabs_reserved_available += 2;
    pthread_mutex_unlock(&bp->lock);

    free(bc);
}

/* To work correctly, the implementation requires that the *n_buffers* input
 * argument is never greater than the buffer pool's *n_buffers_per_slab*. This
 * is typically the case, with one exception taking place when large number of
 * buffers are allocated at init time (e.g. for the UMEM fill queue setup).
 */
static inline u32
bcache_cons_check(struct bcache *bc, u32 n_buffers)
{
    struct bpool *bp = bc->bp;
//    printf("n_buffers: %ld\nbp->params.n_buffers_per_slab: %ld\n", n_buffers, bp->params.n_buffers_per_slab);
    u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
    u64 n_buffers_cons = bc->n_buffers_cons;
    u64 n_slabs_available;
    u64 *slab_full;

    /*
	 * Consumer slab is not empty: Use what's available locally. Do not
	 * look for more buffers from the pool when the ask can only be
	 * partially satisfied.
	 */
    if (n_buffers_cons)
        return (n_buffers_cons < n_buffers) ?
                       n_buffers_cons :
                       n_buffers;

    /*
	 * Consumer slab is empty: look to trade the current consumer slab
	 * (full) for a full slab from the pool, if any is available.
	 */
    pthread_mutex_lock(&bp->lock);
//    printf("Locking bp\n");
    n_slabs_available = bp->n_slabs_available;
    if (!n_slabs_available) {
        printf("Unlocking bp because !n_slabs_available)\n");
        pthread_mutex_unlock(&bp->lock);
        return 0;
    }

    n_slabs_available--;
    slab_full = bp->slabs[n_slabs_available];
    bp->slabs[n_slabs_available] = bc->slab_cons;
    bp->n_slabs_available = n_slabs_available;
//    printf("Unlocking bp because traded a slab from bpool\n");
    pthread_mutex_unlock(&bp->lock);

    bc->slab_cons = slab_full;
    bc->n_buffers_cons = n_buffers_per_slab;
//    printf("bc->n_buffers_cons = %ld\n", bc->n_buffers_cons);
    return n_buffers;
}

static inline u64
bcache_cons(struct bcache *bc)
{
    u64 n_buffers_cons = bc->n_buffers_cons - 1;
    u64 buffer;

    buffer = bc->slab_cons[n_buffers_cons];
    bc->n_buffers_cons = n_buffers_cons;
    return buffer;
}

static inline void
bcache_prod(struct bcache *bc, u64 buffer)
{
    struct bpool *bp = bc->bp;
    u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
    u64 n_buffers_prod = bc->n_buffers_prod;
    u64 n_slabs_available;
    u64 *slab_empty;

    /*
	 * Producer slab is not yet full: store the current buffer to it.
	 */
    if (n_buffers_prod < n_buffers_per_slab) {
        bc->slab_prod[n_buffers_prod] = buffer;
//        printf("bcache_prod: n_buffers_prod: %ld\nn_buffers_per_slab: %ld\n", n_buffers_prod, n_buffers_per_slab);
        bc->n_buffers_prod = n_buffers_prod + 1;
        return;
    }

    /*
	 * Producer slab is full: trade the cache's current producer slab
	 * (full) for an empty slab from the pool, then store the current
	 * buffer to the new producer slab. As one full slab exists in the
	 * cache, it is guaranteed that there is at least one empty slab
	 * available in the pool.
	 */
    pthread_mutex_lock(&bp->lock);
    n_slabs_available = bp->n_slabs_available;
    slab_empty = bp->slabs[n_slabs_available];
    bp->slabs[n_slabs_available] = bc->slab_prod;
//    printf("bcache_prod:     bp->n_slabs_available = n_slabs_available + 1;\n");
    bp->n_slabs_available = n_slabs_available + 1;
    pthread_mutex_unlock(&bp->lock);

    slab_empty[0] = buffer;
    bc->slab_prod = slab_empty;
    bc->n_buffers_prod = 1;
}

/*
 * Port
 *
 * Each of the forwarding ports sits on top of an AF_XDP socket. In order for
 * packet forwarding to happen with no packet buffer copy, all the sockets need
 * to share the same UMEM area, which is used as the buffer pool memory.
 */
#ifndef MAX_BURST_RX
#define MAX_BURST_RX 64
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 64
#endif

struct burst_rx {
    u64 addr[MAX_BURST_RX];
    u32 len[MAX_BURST_RX];
};

struct burst_tx {
    u64 addr[MAX_BURST_TX];
    u32 len[MAX_BURST_TX];
    u32 n_pkts;
};

struct port_params {
    struct xsk_socket_config xsk_cfg;
    struct bpool *bp;
    const char *iface;
    u32 iface_queue;
};

struct port {
    struct port_params params;

    struct bcache *bc;

    struct xsk_ring_cons rxq;
    struct xsk_ring_prod txq;
    struct xsk_ring_prod umem_fq;
    struct xsk_ring_cons umem_cq;
    struct xsk_socket *xsk;
    int umem_fq_initialized;

    u64 n_pkts_rx;
    u64 n_pkts_tx;
};

static void
port_free(struct port *p)
{
    if (!p)
        return;

    /* To keep this example simple, the code to free the buffers from the
	 * socket's receive and transmit queues, as well as from the UMEM fill
	 * and completion queues, is not included.
	 */

    if (p->xsk)
        xsk_socket__delete(p->xsk);

    bcache_free(p->bc);

    free(p);
}

static struct port *
port_init(struct port_params *params)
{
    struct port *p;
    u32 umem_fq_size, pos = 0;
    int status, i;

    /* Memory allocation and initialization. */
    p = static_cast<port *>(calloc(sizeof(struct port), 1));
    if (!p) {
        printf("port_init failed because memory allocation failed.\n");
        return NULL;
    }

    memcpy(&p->params, params, sizeof(p->params));
    umem_fq_size = params->bp->umem_cfg.fill_size;
    printf("port_init: umem_fq_size: %ld\n", umem_fq_size);

    /* bcache. */
    p->bc = bcache_init(params->bp);
    if (!p->bc ||
        (bcache_slab_size(p->bc) < umem_fq_size) ||
        (bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)) {
        port_free(p);
        printf("port_init failed because bcache failed.\n(bcache_slab_size(p->bc) < umem_fq_size) : %s\n"
               "(bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size) : %s",
               ((bcache_slab_size(p->bc) < umem_fq_size) ? "true" : "false"),
               ((bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)  ? "true" : "false")
               );
        return NULL;
    }

    /* xsk socket. */
    status = xsk_socket__create_shared(&p->xsk,
                                       params->iface,
                                       params->iface_queue,
                                       params->bp->umem,
                                       &p->rxq,
                                       &p->txq,
                                       &p->umem_fq,
                                       &p->umem_cq,
                                       &params->xsk_cfg);
    if (status) {
        port_free(p);
        printf("port_init failed because xsk_socket__create_shared failed. Status: %ld\n", status);
        return NULL;
    }

    /* umem fq. */
    xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);

    for (i = 0; i < umem_fq_size; i++)
        *xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
                bcache_cons(p->bc);

    xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
    p->umem_fq_initialized = 1;
    printf("port init: queue: %d, n_buffers_cons: %ld, n_buffers_prod: %ld\n",
           p->params.iface_queue, p->bc->n_buffers_cons, p->bc->n_buffers_prod);
    return p;
}

static inline u32
port_rx_burst(struct port *p, struct burst_rx *b)
{
    u32 n_pkts, pos, i;

    /* Free buffers for FQ replenish. */
    n_pkts = ARRAY_SIZE(b->addr);
//    if (p->bc->n_buffers_cons == 0) {
//        printf("port_rx_burst: p->bc->n_buffers_cons == 0, need to trade slab from pool\n");
//    }
    n_pkts = bcache_cons_check(p->bc, n_pkts);
//    printf("Queue: %ld ons_check got %ld packets\n", p->params.iface_queue,n_pkts);

    if (!n_pkts)
        return 0;

    /* RXQ. */
    n_pkts = xsk_ring_cons__peek(&p->rxq, n_pkts, &pos);
//    printf("Queue: %ld RXQ got %ld packets\n", p->params.iface_queue,n_pkts);

    if (!n_pkts) {
        if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
            struct pollfd pollfd = {
                .fd = xsk_socket__fd(p->xsk),
                .events = POLLIN,
            };

            poll(&pollfd, 1, 0);
        }
        return 0;
    }

    for (i = 0; i < n_pkts; i++) {
        b->addr[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->addr;
        b->len[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->len;
    }

    xsk_ring_cons__release(&p->rxq, n_pkts);
    p->n_pkts_rx += n_pkts;

    /* UMEM FQ. */
//    u64 counter = 0;
    for ( ; ; ) {
//        counter ++;
        int status;

        status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
        if (status == n_pkts) {
//            printf("Queue: %ld Fill Queue got %ld packets, counter = %ld, breaking\n", counter, p->params.iface_queue,n_pkts);
            break;
        }

        if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
            struct pollfd pollfd = {
                .fd = xsk_socket__fd(p->xsk),
                .events = POLLIN,
            };

            poll(&pollfd, 1, 0);
//            printf("Queue: %ld Fill Queue poll for %ld packets, counter = %ld\n", p->params.iface_queue,n_pkts, counter);
        }
//        printf("Queue: %ld Fill Queue busy spinning, counter = %ld\n", p->params.iface_queue,n_pkts, counter);
    }

    for (i = 0; i < n_pkts; i++)
        *xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
                bcache_cons(p->bc);

    xsk_ring_prod__submit(&p->umem_fq, n_pkts);
//    printf("Queue: %ld rx burst got %ld packets\n", p->params.iface_queue,n_pkts);
    return n_pkts;
}

static inline void
port_tx_burst(struct port *p, struct burst_tx *b, struct port * p2)
{
    u32 n_pkts, pos, i;
    int status;

    /* UMEM CQ. */
    n_pkts = p->params.bp->umem_cfg.comp_size;

    n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

    for (i = 0; i < n_pkts; i++) {
        u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

        bcache_prod(p->bc, addr);
    }

    xsk_ring_cons__release(&p->umem_cq, n_pkts);

    /* TXQ. */
    n_pkts = b->n_pkts;

//    u64 counter = 0;
    for ( ; ; ) {
//        counter ++;
        status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
        if (status == n_pkts) {
//            printf("Queue: %ld TX Queue got %ld packets, counter = %ld, breaking\n", counter, p->params.iface_queue,n_pkts);
            break;
        }

        if (xsk_ring_prod__needs_wakeup(&p->txq)) {
            sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT,
                   NULL, 0);
//            printf("Queue: %ld TX sendto %ld packets, counter = %ld\n", counter, p->params.iface_queue,n_pkts);
        }
//        printf("Queue: %ld TX busy spinning, counter = %ld\n", counter, p->params.iface_queue,n_pkts);
    }

    for (i = 0; i < n_pkts; i++) {
        xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
        xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
    }

    xsk_ring_prod__submit(&p->txq, n_pkts);
    if (xsk_ring_prod__needs_wakeup(&p->txq))
        sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    p->n_pkts_tx += n_pkts;
    if (p2->params.iface_queue != p->params.iface_queue) {
        printf("TX Queue: %ld, RX Queue: %ld tx burst sent %ld packets\n", p2->params.iface_queue, p->params.iface_queue, n_pkts);
    }
}

/*
 * Thread
 *
 * Packet forwarding threads.
 */
#ifndef MAX_PORTS_PER_THREAD
#define MAX_PORTS_PER_THREAD 16
#endif

struct thread_data {
    struct port *ports_rx[MAX_PORTS_PER_THREAD];
    struct port *ports_tx[MAX_PORTS_PER_THREAD];
    u32 n_ports_rx;
    struct burst_rx burst_rx;
    struct burst_tx burst_tx[MAX_PORTS_PER_THREAD];
    u32 cpu_core_id;
    int quit;
};

static void swap_mac_addresses(void *data)
{
    struct ether_header *eth = (struct ether_header *)data;
    struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
    struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
    struct ether_addr tmp;

    tmp = *src_addr;
    *src_addr = *dst_addr;
    *dst_addr = tmp;
}

static bool process_packet(void *pkt, uint32_t len/*,struct xsk_socket_info *xsk,*/
                           /*uint64_t addr, , int* fd*/
                           )
{
//    printf(">>>>>>>>>>  Begin processing packet  >>>>>>>>>>\n");
    bpf_lpm_trie_key k;
    if (true) {
//        printf("Process packets: inside if (true)\n");
        /*
         * TODO: Parse packet here, get VNI, IP, MAC, lookup locally in DB, and replace neigbor host IP if found;
         * if NOT found, drop packet and remotely GET from Arion Master.
         * */
        int ret;
        uint32_t tx_idx = 0;
        uint8_t tmp_mac[ETH_ALEN];
        // parse outer eth header
        struct ethhdr *eth = (struct ethhdr *) pkt;

        if (ntohs(eth->h_proto) != ETH_P_IP) {
//            printf("Process packets: returning false for this packet as it is NOT IP %u\n", ntohs(eth->h_proto));
            return false;
        }
//        printf("Packet length: %ld\n", len);
//        printf("Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//               "eth size: %d\n",
//               eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//               eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//               bpf_ntohs(eth->h_proto),
//               sizeof(*eth));

        // parse outer IP header
        struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
        struct in_addr outer_ip_src;
        outer_ip_src.s_addr = ip->saddr;
        struct in_addr outer_ip_dest;
        outer_ip_dest.s_addr = ip->daddr;
//        printf("Outer ip src: %s,",inet_ntoa(outer_ip_src));
//        printf("ip dest: %s\n"
//               "Outer ip ihl: %d, version: %d\n",
//                inet_ntoa(outer_ip_dest),
//                ip->ihl, ip->version);

        // parse UDP header
        struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//        printf("UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//               udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));

        // parse VXLAN header
        struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//        printf("VNI: %ld, \n",trn_get_vni(vxlan->vni));

        // parse inner eth header
        struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//        printf("inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//               inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//               inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//               inner_eth->h_proto);

        if (ntohs(inner_eth->h_proto) == ETH_P_ARP) {
            // parse inner arp header
            arp_message *arp_msg = (struct arp_message *)(inner_eth + 1);
//            struct in_addr arp_src_ip;
//            arp_src_ip.s_addr = arp_msg->spa;
            struct in_addr arp_dest_ip;
            arp_dest_ip.s_addr = arp_msg->tpa;
//            printf("arp op: %d\n",
//                   bpf_htons(arp_msg->op));
//            printf("arp source ip: %s, \n",
//                   inet_ntoa(arp_src_ip/*inner_arp_dest_ip*/)
//            );
//            printf("arp dest ip: %s, \n",
//                   inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/)
//            );
            endpoint_key_t epkey;
            epkey.vni = trn_get_vni(vxlan->vni);
            struct sockaddr_in ep_ip;
            inet_pton(AF_INET, inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
            epkey.ip = ep_ip.sin_addr.s_addr;
            auto ep_value = db_client::get_instance().GetNeighborInMemory(epkey);
            //            endpoint_t ep_value;
            //            ep_value = db_client::get_instance().GetNeighbor(trn_get_vni(vxlan->vni), inet_ntoa(arp_dest_ip));
            if (ep_value.hip != 0) {
                // we now have key and value, can modify the packet and update the map now.
                //                int ebpf_rc = bpf_map_update_elem((*fd), &epkey, &ep_value, BPF_ANY);
                //                printf("AF_XDP: Inserted this neighbor into map: vip: %s, vni: %d, ebpf_rc: %d\n",
                //                       inet_ntoa(arp_src_ip), trn_get_vni(vxlan->vni), 0);

                /* Modify pkt for inner ARP response */
                struct in_addr ep_ip_addr/*, ep_host_ip_addr*/;
                ep_ip_addr.s_addr = epkey.ip;
//                ep_host_ip_addr.s_addr = ep_value.hip;
//                printf("Retrived this endpoint: HIP: %s ", inet_ntoa(ep_host_ip_addr));
//                printf("IP: %s, host_mac: %x:%x:%x:%x:%x:%x, mac: %x:%x:%x:%x:%x:%x\n",
//                       inet_ntoa(ep_ip_addr),
//                       ep_value.hmac[0],ep_value.hmac[1],ep_value.hmac[2],ep_value.hmac[3],ep_value.hmac[4],ep_value.hmac[5],
//                       ep_value.mac[0],ep_value.mac[1],ep_value.mac[2],ep_value.mac[3],ep_value.mac[4],ep_value.mac[5]
//                );
                arp_msg->op = bpf_htons(ARPOP_REPLY);
                trn_set_mac(arp_msg->tha, arp_msg->sha);
                trn_set_mac(arp_msg->sha, ep_value.mac);

                __u32 tmp_ip = arp_msg->spa;//*sip;
                arp_msg->spa = arp_msg->tpa;//*tip;
                arp_msg->tpa = tmp_ip;

                /* Modify inner EitherHdr, pretend it's from target */
                trn_set_dst_mac(inner_eth, inner_eth->h_source);
                trn_set_src_mac(inner_eth, ep_value.mac);

                /* Keep overlay header, swap outer IP header */
                trn_set_src_dst_ip_csum(ip, ip->daddr, ip->saddr, (eth + len));
                trn_swap_src_dst_mac(pkt);

                /*
             * Packet modification finished, read packet content again, in order to verify the mod
             * */

//                struct ethhdr *eth = (struct ethhdr *) pkt;
//
//                if (ntohs(eth->h_proto) != ETH_P_IP) {
////                    printf("%s\n", "AFTER MOD: returning false for this packet as it is NOT IP");
//                    return false;
//                }
//                printf("AFTER MOD: Packet length: %ld\n", len);
//                printf("AFTER MOD: Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//                       "eth size: %d\n",
//                       eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//                       eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//                       bpf_ntohs(eth->h_proto),
//                       sizeof(*eth));
//
//                // parse outer IP header
//                struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
//                struct in_addr outer_ip_src;
//                outer_ip_src.s_addr = ip->saddr;
//                struct in_addr outer_ip_dest;
//                outer_ip_dest.s_addr = ip->daddr;
//                printf("AFTER MOD: Outer ip src: %s,", inet_ntoa(outer_ip_src));
//                printf("ip dest: %s\n"
//                       "AFTER MOD: Outer ip ihl: %d, version: %d\n",
//                       inet_ntoa(outer_ip_dest),
//                       ip->ihl, ip->version);
//
//                // parse UDP header
//                struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//                printf("AFTER MOD: UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//                       udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));
//
//                // parse VXLAN header
//                struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//                printf("AFTER MOD: VNI: %ld, \n",trn_get_vni(vxlan->vni));
//
//                // parse inner eth header
//                struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//                printf("AFTER MOD: inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//                       inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//                       inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//                       inner_eth->h_proto);
//
//                // parse inner arp header
//                arp_message *arp_msg = (struct arp_message *)(inner_eth + 1);
//                struct in_addr arp_src_ip;
//                arp_src_ip.s_addr = arp_msg->spa;
//                struct in_addr arp_dest_ip;
//                arp_dest_ip.s_addr = arp_msg->tpa;
//                printf("AFTER MOD: arp op: %d\n",
//                       bpf_htons(arp_msg->op));
//                printf("AFTER MOD: arp source ip: %s, \n",
//                       inet_ntoa(arp_src_ip/*inner_arp_dest_ip*/)
//                );
//                printf("AFTER MOD: arp dest ip: %s, \n",
//                       inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/)
//                );
                /* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

//                printf("<<<<<<<<<<  Finished processing packet  <<<<<<<<<<\n");

                return true;
            } else {
                printf("Can't find endpoint!\n");
                return false;
            }
        }
        else if (ntohs(inner_eth->h_proto) == ETH_P_IP) {
            // parse inner IP header
            struct iphdr *inner_ip = (struct iphdr *)(inner_eth + 1 /*sizeof(*inner_eth)*/);


//            struct in_addr inner_ip_src;
//            inner_ip_src.s_addr = inner_ip->saddr;
            struct in_addr inner_ip_dest;
            inner_ip_dest.s_addr = inner_ip->daddr;
//            printf("Inner IP src: %s\n", inet_ntoa(inner_ip_src));
//            printf("Inner IP dest: %s\n", inet_ntoa(inner_ip_dest));
            endpoint_key_t epkey;
            epkey.vni = trn_get_vni(vxlan->vni);
            struct sockaddr_in ep_ip;
            inet_pton(AF_INET, inet_ntoa(inner_ip_dest/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
            epkey.ip = ep_ip.sin_addr.s_addr;


            sg_cidr_key_t sg_key;
            sg_key.protocol = inner_ip->protocol;
            sg_key.ip = ep_ip.sin_addr.s_addr;
            sg_key.vni = epkey.vni;
            sg_key.direction = 1; // how to express goingout/coming in?
            if (sg_key.protocol == IPPROTO_TCP) {
                struct tcphdr *inner_tcp = (struct tcphdr *)(inner_ip + 1);
                sg_key.port = bpf_htons(inner_tcp->dest);
                sg_key.prefixlen = 136;
                // how about lpm_key.data?
            } else if (sg_key.protocol == IPPROTO_UDP) {
                struct udphdr *inner_udp = (struct udphdr *)(inner_ip + 1);
                sg_key.port = bpf_htons(inner_udp->dest);
                sg_key.prefixlen = 136;
                // how about lpm_key.data?
            }



            auto ep_value = db_client::get_instance().GetNeighborInMemory(epkey);
            //            endpoint_t ep_value;
            //            ep_value = db_client::get_instance().GetNeighbor(trn_get_vni(vxlan->vni), inet_ntoa(inner_ip_dest));

            if (ep_value.hip != 0) {
                //                epkey.vni = trn_get_vni(vxlan->vni);
                //                struct sockaddr_in ep_ip;
                //                inet_pton(AF_INET, inet_ntoa(inner_ip_dest/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
                //                epkey.ip = ep_ip.sin_addr.s_addr;
                // we now have key and value, can modify the packet and update the map now.
                //                int ebpf_rc = bpf_map_update_elem((*fd), &epkey, &ep_value, BPF_ANY);
                //                printf("AF_XDP: Inserted this neighbor into map: vip: %s, vni: %d, ebpf_rc: %d\n",
                //                       inet_ntoa(inner_ip_dest), trn_get_vni(vxlan->vni), 0);

//                struct in_addr ep_ip_addr, ep_host_ip_addr;
//                ep_ip_addr.s_addr = epkey.ip;
//                ep_host_ip_addr.s_addr = ep_value.hip;
//                printf("Retrived this endpoint: HIP: %s,", inet_ntoa(ep_host_ip_addr));
//                printf("IP: %s, host_mac: %x:%x:%x:%x:%x:%x, mac: %x:%x:%x:%x:%x:%x\n",
//                       inet_ntoa(ep_ip_addr),
//                       ep_value.hmac[0],ep_value.hmac[1],ep_value.hmac[2],ep_value.hmac[3],ep_value.hmac[4],ep_value.hmac[5],
//                       ep_value.mac[0],ep_value.mac[1],ep_value.mac[2],ep_value.mac[3],ep_value.mac[4],ep_value.mac[5]
//                );

                /* Modify inner EitherHdr, pretend it's from target */
                trn_set_dst_mac(inner_eth, ep_value.mac);

                /* Keep overlay header, update outer header destinations */
                trn_set_src_dst_ip_csum(ip, ip->daddr, ep_value.hip, (eth + len));
                trn_set_src_mac(eth, eth->h_dest);
                trn_set_dst_mac(eth, ep_value.hmac);

                /*
             * Packet modification finished, read packet content again, in order to verify the mod
             * */

//                struct ethhdr *eth = (struct ethhdr *) pkt;
//
//                if (ntohs(eth->h_proto) != ETH_P_IP) {
////                    printf("%s\n", "AFTER MOD: returning false for this packet as it is NOT IP");
//                    return false;
//                }
//                printf("AFTER MOD: Packet length: %ld\n", len);
//                printf("AFTER MOD: Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//                       "eth size: %d\n",
//                       eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//                       eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//                       bpf_ntohs(eth->h_proto),
//                       sizeof(*eth));
//
////                 parse outer IP header
//                struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
//                struct in_addr outer_ip_src;
//                outer_ip_src.s_addr = ip->saddr;
//                struct in_addr outer_ip_dest;
//                outer_ip_dest.s_addr = ip->daddr;
//                printf("AFTER MOD: Outer ip src: %s", inet_ntoa(outer_ip_src));
//                printf("ip dest: %s\n"
//                       "AFTER MOD: Outer ip ihl: %d, version: %d\n",
//                       inet_ntoa(outer_ip_dest),
//                       ip->ihl, ip->version);
//
//                // parse UDP header
//                struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//                printf("AFTER MOD: UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//                       udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));
//
//                // parse VXLAN header
//                struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//                printf("AFTER MOD: VNI: %ld, \n",trn_get_vni(vxlan->vni));
//
//                // parse inner eth header
//                struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//                printf("AFTER MOD: inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//                       inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//                       inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//                       inner_eth->h_proto);
//
//                // parse inner IP header
//                struct iphdr *inner_ip = (struct iphdr *)(inner_eth + 1 /*sizeof(*inner_eth)*/);
//                struct in_addr inner_ip_src, inner_ip_dest;
//                inner_ip_src.s_addr = inner_ip->saddr;
//                inner_ip_dest.s_addr = inner_ip->daddr;
//                printf("AFTER MOD: Inner IP src: %s\n", inet_ntoa(inner_ip_src));
//                printf("AFTER MOD: Inner IP dest: %s\n", inet_ntoa(inner_ip_dest));
                /* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

//                printf("<<<<<<<<<<  Finished processing packet  <<<<<<<<<<\n");

                return true;
            } else {
                printf("Can't find endpoint!\n");
                return false;
            }
        }

        printf("Neither ARP or IP, returning false.\n");
        return false;
    }
    printf("process packet: how is this false?\n");
    return false;
}



static void *
thread_func(void *arg)
{
    struct thread_data *t = static_cast<thread_data *>(arg);
    cpu_set_t cpu_cores;
    u32 i;
    CPU_ZERO(&cpu_cores);
    CPU_SET(t->cpu_core_id, &cpu_cores);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
    for (int j = 0 ; j < t->n_ports_rx ; j ++) {
        struct port * port_rx = t->ports_rx[j];
        printf("port: %ld, tx queue needs wake up: %ld, fill queue needs wake up :%ld\n",
               port_rx->params.iface_queue, xsk_ring_prod__needs_wakeup(&port_rx->txq) , xsk_ring_prod__needs_wakeup(&port_rx->umem_fq));
        if (port_rx->bc->n_buffers_cons == 0) {
            port_rx->bc->n_buffers_cons = 4096;
            printf("Manually setting port %d n_buffer_cons to 4096\n", port_rx->params.iface_queue);
        }
    }


    for (i = 0; !t->quit; i = (i + 1) & (t->n_ports_rx - 1)) {
        struct port *port_rx = t->ports_rx[i];
        struct port *port_tx = t->ports_tx[i];
//        printf("Thread: %ld, port rx: %ld, port tx: %ld\n",
//               t->cpu_core_id, port_rx->params.iface_queue, port_tx->params.iface_queue);
        struct burst_rx *brx = &t->burst_rx;
        struct burst_tx *btx = &t->burst_tx[i];
        u32 n_pkts, j;

        /* RX. */
        n_pkts = port_rx_burst(port_rx, brx);
        if (!n_pkts) {
//            printf("thead %ld got no packets in rx_burst, continue\n", t->cpu_core_id );
            continue;
        }

        /* Process & TX. */
        for (j = 0; j < n_pkts; j++) {
//            printf("Queue %ld getting the %ld th packet\n", port_rx->params.iface_queue, j);
            u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
            u8 *pkt = static_cast<u8 *>(xsk_umem__get_data(port_rx->params.bp->addr, addr));
//            printf("Queue %ld processing the %ld th packet\n", port_rx->params.iface_queue, j);

            process_packet(pkt, brx->len[j]);
//            swap_mac_addresses(pkt);

            btx->addr[btx->n_pkts] = brx->addr[j];
            btx->len[btx->n_pkts] = brx->len[j];
            btx->n_pkts++;

        }
        if (btx->n_pkts > 0/*== MAX_BURST_TX*/) {
            port_tx_burst(port_tx, btx, port_rx);
            btx->n_pkts = 0;
        }
    }

    return NULL;
}

/*
 * Process
 */
static const struct bpool_params  bpool_params_default = {
    .n_buffers = 192 /* this number should be set to 64 * (number_of_cores / 8)*/ * 1024,
    .buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
    .mmap_flags = 0,

    .n_users_max = 16/*24*/,
    .n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
};

static const struct xsk_umem_config umem_cfg_default = {
    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,  //* 2,
    .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = XDP_RING_NEED_WAKEUP,
};

static const struct port_params port_params_default = {
    .xsk_cfg = {
            .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
            .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
            .libbpf_flags = 0, //.libxdp_flags
            .xdp_flags = XDP_FLAGS_DRV_MODE,
            .bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    },

    .bp = NULL,
    .iface = NULL,
    .iface_queue = 0,
};

#ifndef MAX_PORTS
#define MAX_PORTS 64
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 64
#endif

static struct bpool_params bpool_params;
static struct xsk_umem_config umem_cfg;
static struct bpool *bp;

static struct port_params port_params[MAX_PORTS];
static struct port *ports[MAX_PORTS];
static u64 n_pkts_rx[MAX_PORTS];
static u64 n_pkts_tx[MAX_PORTS];
static int n_ports;

static pthread_t threads[MAX_THREADS];
static struct thread_data thread_data[MAX_THREADS];
static int n_threads;

static void
print_usage(char *prog_name)
{
    const char *usage =
            "Usage:\n"
            "\t%s [ -b SIZE ] -c CORE -i INTERFACE [ -q QUEUE ]\n"
            "\n"
            "-c CORE        CPU core to run a packet forwarding thread\n"
            "               on. May be invoked multiple times.\n"
            "\n"
            "-b SIZE        Number of buffers in the buffer pool shared\n"
            "               by all the forwarding threads. Default: %u.\n"
            "\n"
            "-i INTERFACE   Network interface. Each (INTERFACE, QUEUE)\n"
            "               pair specifies one forwarding port. May be\n"
            "               invoked multiple times.\n"
            "\n"
            "-q QUEUE       Network interface queue for RX and TX. Each\n"
            "               (INTERFACE, QUEUE) pair specified one\n"
            "               forwarding port. Default: %u. May be invoked\n"
            "               multiple times.\n"
            "\n";
    printf(usage,
           prog_name,
           bpool_params_default.n_buffers,
           port_params_default.iface_queue);
}

static int
parse_args(int argc, char **argv)
{
    struct option lgopts[] = {
        { NULL,  0, 0, 0 }
    };
    int opt, option_index;

    /* Parse the input arguments. */
    for ( ; ;) {
        opt = getopt_long(argc, argv, "c:i:q:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'b':
            bpool_params.n_buffers = atoi(optarg);
            break;

        case 'c':
            if (n_threads == MAX_THREADS) {
                printf("Max number of threads (%d) reached.\n",
                       MAX_THREADS);
                return -1;
            }

            thread_data[n_threads].cpu_core_id = atoi(optarg);
            n_threads++;
            break;

        case 'i':
            if (n_ports == MAX_PORTS) {
                printf("Max number of ports (%d) reached.\n",
                       MAX_PORTS);
                return -1;
            }

            port_params[n_ports].iface = optarg;
            port_params[n_ports].iface_queue = 0;
            n_ports++;
            break;

        case 'q':
            if (n_ports == 0) {
                printf("No port specified for queue.\n");
                return -1;
            }
            port_params[n_ports - 1].iface_queue = atoi(optarg);
            break;

        default:
            printf("Illegal argument.\n");
            return -1;
        }
    }

    optind = 1; /* reset getopt lib */

    /* Check the input arguments. */
    if (!n_ports) {
        printf("No ports specified.\n");
        return -1;
    }

    if (!n_threads) {
        printf("No threads specified.\n");
        return -1;
    }

    if (n_ports % n_threads) {
        printf("Ports cannot be evenly distributed to threads.\n");
        return -1;
    }

    return 0;
}

static void
print_port(u32 port_id)
{
    struct port *port = ports[port_id];
    int option;
    socklen_t option_length  = sizeof(option);
    getsockopt(xsk_socket__fd(port->xsk), SOL_XDP, XDP_OPTIONS, &option, (&option_length));
    printf("Port %u: interface = %s, queue = %u, zero_copy_enabled: %s\n",
           port_id, port->params.iface, port->params.iface_queue,
           ((option == XDP_OPTIONS_ZEROCOPY ? "true" : "false")));
}

static void
print_thread(u32 thread_id)
{
    struct thread_data *t = &thread_data[thread_id];
    u32 i;

    printf("Thread %u (CPU core %u): ",
           thread_id, t->cpu_core_id);

    for (i = 0; i < t->n_ports_rx; i++) {
        struct port *port_rx = t->ports_rx[i];
        struct port *port_tx = t->ports_tx[i];

        printf("(%s, %u) -> (%s, %u), ",
               port_rx->params.iface,
               port_rx->params.iface_queue,
               port_tx->params.iface,
               port_tx->params.iface_queue);
    }

    printf("\n");
}

static void
print_port_stats_separator(void)
{
    printf("+-%4s-+-%12s-+-%13s-+-%12s-+-%13s-+\n",
           "----",
           "------------",
           "-------------",
           "------------",
           "-------------");
}

static void
print_port_stats_header(void)
{
    print_port_stats_separator();
    printf("| %4s | %12s | %13s | %12s | %13s |\n",
           "Port",
           "RX packets",
           "RX rate (pps)",
           "TX packets",
           "TX_rate (pps)");
    print_port_stats_separator();
}

static void
print_port_stats_trailer(void)
{
    print_port_stats_separator();
    printf("\n");
}

static void
print_port_stats(int port_id, u64 ns_diff)
{
    struct port *p = ports[port_id];
    double rx_pps, tx_pps;

    rx_pps = (p->n_pkts_rx - n_pkts_rx[port_id]) * 1000000000. / ns_diff;
    tx_pps = (p->n_pkts_tx - n_pkts_tx[port_id]) * 1000000000. / ns_diff;

    printf("| %4d | %12llu | %13.0f | %12llu | %13.0f |\n",
           port_id,
           p->n_pkts_rx,
           rx_pps,
           p->n_pkts_tx,
           tx_pps);

    n_pkts_rx[port_id] = p->n_pkts_rx;
    n_pkts_tx[port_id] = p->n_pkts_tx;
}

static void
print_port_stats_all(u64 ns_diff)
{
    int i;

    print_port_stats_header();
    for (i = 0; i < n_ports; i++)
        print_port_stats(i, ns_diff);
    print_port_stats_trailer();
}

static int quit;

static void
signal_handler(int sig)
{
    quit = 1;
}

//static void remove_xdp_program(void)
//{
//    struct xdp_multiprog *mp;
//    int i, err;
//
//    for (i = 0 ; i < n_ports; i++) {
//        mp = xdp_multiprog__get_from_ifindex(if_nametoindex(port_params[i].iface));
//        if (IS_ERR_OR_NULL(mp)) {
//            printf("No XDP program loaded on %s\n", port_params[i].iface);
//            continue;
//        }
//
//        err = xdp_multiprog__detach(mp);
//        if (err)
//            printf("Unable to detach XDP program: %s\n", strerror(-err));
//    }
//}

void* af_xdp_user_multi_thread::run_af_xdp_multi_threaded(void* args/*int argc, char **argv*/)
{
    struct timespec time;
    u64 ns0;
    int i;

    std::string table_name_neighbor_ebpf_map = "/sys/fs/bpf/endpoints_map";
    int fd_neighbor_ebpf_map = bpf_obj_get(table_name_neighbor_ebpf_map.c_str());

    std::string table_name_sg_ebpf_map = "/sys/fs/bpf/security_group_map";
    int fd_security_group_ebpf_map = bpf_obj_get(table_name_sg_ebpf_map.c_str());

    printf("endpoints map fd: %ld, sg map fd: %ld\n", fd_neighbor_ebpf_map, fd_security_group_ebpf_map);


    if (fd_neighbor_ebpf_map <= 0 || fd_security_group_ebpf_map <= 0 ) {
        printf("fd_neighbor_ebpf_map: %ld, fd_security_group_ebpf_map: %ld, exiting\n"
               , fd_neighbor_ebpf_map, fd_security_group_ebpf_map);
//        exit(-1);
    }

    /* Parse args. */
    memcpy(&bpool_params, &bpool_params_default,
           sizeof(struct bpool_params));
    memcpy(&umem_cfg, &umem_cfg_default,
           sizeof(struct xsk_umem_config));
//    umem_cfg.flags |= (XDP_RING_NEED_WAKEUP/*XDP_USE_NEED_WAKEUP*/ );
    for (i = 0; i < MAX_PORTS; i++)
        memcpy(&port_params[i], &port_params_default,
               sizeof(struct port_params));

//    if (parse_args(argc, argv)) {
//        print_usage(argv[0]);
//        return -1;
//    }
    auto number_of_cores = std::thread::hardware_concurrency();
    printf("This machine has %ld cores\n", number_of_cores);
    // leave 8 cores for the rest of the system.
    n_ports = number_of_cores > 8 ? (number_of_cores - 8) : 0;

    if (n_ports == 0) {
        printf("This machine has too little number of cores(%ld), not good for AF_XDP. Exiting\n", number_of_cores);
        exit(-1);
    }

    printf("After leaving 8 cores for other applications, we are now setting the interface to have %ld AF_XDP sockets.\n", n_ports);

    string set_nic_queue_command_template = "ethtool -L enp4s0f1 combined %ld";
    char set_nic_queue_command[100];
    sprintf(set_nic_queue_command, "ethtool -L enp4s0f1 combined %ld", n_ports);
    printf("Executing system command: %s\n", set_nic_queue_command);
    int set_nic_queue_command_rc = system(set_nic_queue_command);

    if (set_nic_queue_command_rc!=EXIT_SUCCESS) {
        printf("set nic queue command failed(%ld)! Exiting\n", set_nic_queue_command_rc);
        exit(-1);
    }

    // using 1 thread per iface + iface_queue
    n_threads = n_ports; // get number of cores of this machine.

    for ( int i = 0 ; i < n_ports ; i ++) {
        port_params[i].iface = "enp4s0f1";
        port_params[i].iface_queue = i;
        thread_data[i].cpu_core_id = i;
    }


    /* Buffer pool initialization. */
    bp = bpool_init(&bpool_params, &umem_cfg);
    if (!bp) {
        printf("Buffer pool initialization failed.\n");
        return args;
    }
    printf("Buffer pool created successfully.\n");

    /* Ports initialization. */
    for (i = 0; i < MAX_PORTS; i++)
        port_params[i].bp = bp;

    for (i = 0; i < n_ports; i++) {
        ports[i] = port_init(&port_params[i]);
        if (!ports[i]) {
            printf("Port %d initialization failed.\n", i);
            return args;
        }
        print_port(i);
    }
    printf("All ports created successfully.\n");

    /* Threads. */
    for (i = 0; i < n_threads; i++) {
        struct thread_data *t = &thread_data[i];
        u32 n_ports_per_thread = n_ports / n_threads, j;

        for (j = 0; j < n_ports_per_thread; j++) {
            t->ports_rx[j] = ports[i * n_ports_per_thread + j];
            t->ports_tx[j] = ports[i * n_ports_per_thread +
                                   (j + 1) % n_ports_per_thread];
//            printf("Thread: %ld has rx port: %ld, tx port: %ld\n",
//                   i, t->ports_rx[j]->params.iface_queue, t->ports_tx[j]->params.iface_queue);
        }

        t->n_ports_rx = n_ports_per_thread;

        print_thread(i);
    }

    for (i = 0; i < n_threads; i++) {
        int status;

        status = pthread_create(&threads[i],
                                NULL,
                                thread_func,
                                &thread_data[i]);
        if (status) {
            printf("Thread %d creation failed.\n", i);
            return args;
        }
    }
    printf("All threads created successfully.\n");

    /* Print statistics. */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);

    clock_gettime(CLOCK_MONOTONIC, &time);
    ns0 = time.tv_sec * 1000000000UL + time.tv_nsec;
    for ( ; !quit; ) {
        u64 ns1, ns_diff;

        sleep(10);
        clock_gettime(CLOCK_MONOTONIC, &time);
        ns1 = time.tv_sec * 1000000000UL + time.tv_nsec;
        ns_diff = ns1 - ns0;
        ns0 = ns1;

        print_port_stats_all(ns_diff);
    }

    /* Threads completion. */
    printf("Quit.\n");
    for (i = 0; i < n_threads; i++)
        thread_data[i].quit = 1;

    for (i = 0; i < n_threads; i++)
        pthread_join(threads[i], NULL);

    for (i = 0; i < n_ports; i++)
        port_free(ports[i]);

    bpool_free(bp);

//    remove_xdp_program();

    return args;
}
