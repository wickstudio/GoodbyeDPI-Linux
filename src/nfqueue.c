/*
 * NFQUEUE Wrapper for GoodbyeDPI-Linux
 *
 * Replaces WinDivert packet interception with Linux Netfilter Queue.
 * Uses libnetfilter_queue to receive packets from the kernel,
 * process them, and set verdicts (accept/drop/modify).
 *
 * Also provides raw socket functionality for injecting fake packets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "nfqueue.h"
#include "goodbyedpi.h"

/* NF_INET hook constants (from linux/netfilter.h, defined here to avoid
 * header conflicts between linux/in.h and netinet/in.h) */
#ifndef NF_INET_LOCAL_OUT
#define NF_INET_LOCAL_OUT   3
#endif
#ifndef NF_INET_POST_ROUTING
#define NF_INET_POST_ROUTING 4
#endif
#ifndef NF_DROP
#define NF_DROP   0
#endif
#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif

/* NFQUEUE handle structure */
struct nfqueue_handle {
    struct nfq_handle *nfq_h;
    struct nfq_q_handle *nfq_qh;
    uint16_t queue_num;
    nfqueue_callback_t callback;
    void *user_data;
    int fd;
    volatile int running;
    /* Store verdict info for current packet being processed */
    int current_verdict;
    unsigned char *current_modified_data;
    size_t current_modified_len;
};

/* Raw socket for packet injection */
static int raw_sock_fd = -1;

/* Firewall mark value used to tag injected packets so iptables skips them */
#define RAWSOCK_MARK 0x10

/**
 * Initialize the raw socket for fake packet injection.
 */
int raw_socket_init(void) {
    if (raw_sock_fd >= 0)
        return 0; /* Already initialized */

    /* Must use AF_INET with IP_HDRINCL for raw IP injection */
    raw_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock_fd < 0) {
        perror("raw_socket_init: socket(AF_INET, SOCK_RAW)");
        return -1;
    }
    int one = 1;
    if (setsockopt(raw_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("raw_socket_init: setsockopt IP_HDRINCL");
        close(raw_sock_fd);
        raw_sock_fd = -1;
        return -1;
    }

    /* Mark all packets from this socket so iptables can skip them
     * (prevents re-interception by NFQUEUE rules) */
    int mark = RAWSOCK_MARK;
    if (setsockopt(raw_sock_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        perror("raw_socket_init: setsockopt SO_MARK");
        close(raw_sock_fd);
        raw_sock_fd = -1;
        return -1;
    }

    return 0;
}

/**
 * Send a raw packet directly on the wire.
 * For AF_INET raw sockets, we send to the destination from the IP header.
 */
int raw_socket_send(const char *packet, size_t packet_len) {
    if (raw_sock_fd < 0)
        return -1;

    if (packet_len < sizeof(struct iphdr))
        return -1;

    uint8_t version = (*(const uint8_t *)packet) >> 4;

    if (version == 4) {
        const struct iphdr *iph = (const struct iphdr *)packet;
        struct sockaddr_in dst_addr;
        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr.s_addr = iph->daddr;

        ssize_t sent = sendto(raw_sock_fd, packet, packet_len, 0,
                              (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        if (sent < 0) {
            debug("raw_socket_send IPv4 error: %s\n", strerror(errno));
            return -1;
        }
        debug("Sent raw IPv4 packet: %zd bytes\n", sent);
        return 0;
    }
    else if (version == 6) {
        /* For IPv6, we need a separate raw socket */
        int sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock6 < 0) {
            debug("raw_socket_send: can't create IPv6 raw socket: %s\n", strerror(errno));
            return -1;
        }
        int on = 1;
        setsockopt(sock6, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on));

        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)packet;
        struct sockaddr_in6 dst_addr;
        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sin6_family = AF_INET6;
        memcpy(&dst_addr.sin6_addr, &ip6h->ip6_dst, 16);

        ssize_t sent = sendto(sock6, packet, packet_len, 0,
                              (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        close(sock6);
        if (sent < 0) {
            debug("raw_socket_send IPv6 error: %s\n", strerror(errno));
            return -1;
        }
        debug("Sent raw IPv6 packet: %zd bytes\n", sent);
        return 0;
    }

    return -1;
}

/**
 * Close the raw socket.
 */
void raw_socket_close(void) {
    if (raw_sock_fd >= 0) {
        close(raw_sock_fd);
        raw_sock_fd = -1;
    }
}

/* Global storage for current packet verdict in callback */
static struct nfqueue_handle *g_current_handle = NULL;
static uint32_t g_current_packet_id = 0;

/**
 * NFQUEUE callback function called for each received packet.
 * Determines packet direction and invokes user callback.
 */
static int nfq_pkt_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                            struct nfq_data *nfa, void *data)
{
    (void)nfmsg;
    struct nfqueue_handle *handle = (struct nfqueue_handle *)data;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;
    uint32_t id = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0) {
        /* Can't get payload, just accept */
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }

    /* Determine direction from hook number:
     * NF_INET_LOCAL_OUT (3) / NF_INET_POST_ROUTING (4) = outbound
     * NF_INET_PRE_ROUTING (0) / NF_INET_LOCAL_IN (1) = inbound
     */
    int is_outbound = 0;
    if (ph) {
        uint8_t hook = ph->hook;
        if (hook == NF_INET_LOCAL_OUT || hook == NF_INET_POST_ROUTING) {
            is_outbound = 1;
        }
    }

    /* Call user callback */
    int verdict = VERDICT_ACCEPT;
    if (handle->callback) {
        /* Copy payload so the callback can modify it */
        unsigned char *pkt_copy = malloc((size_t)payload_len);
        if (pkt_copy) {
            memcpy(pkt_copy, payload, (size_t)payload_len);

            /* Store current handle for potential modifications */
            g_current_handle = handle;
            g_current_packet_id = id;

            verdict = handle->callback(
                handle->queue_num,
                pkt_copy,
                (size_t)payload_len,
                is_outbound,
                handle->user_data
            );

            if (verdict == VERDICT_DROP) {
                nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            else {
                /* Accept with potentially modified data */
                nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)payload_len, pkt_copy);
            }
            free(pkt_copy);
        }
        else {
            nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
    }
    else {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    return 0;
}

/**
 * Open an NFQUEUE and register a callback.
 */
nfqueue_handle_t *nfqueue_open(uint16_t queue_num, nfqueue_callback_t callback, void *user_data) {
    nfqueue_handle_t *handle = calloc(1, sizeof(nfqueue_handle_t));
    if (!handle) {
        perror("nfqueue_open: calloc");
        return NULL;
    }

    handle->queue_num = queue_num;
    handle->callback = callback;
    handle->user_data = user_data;

    /* Open NFQUEUE handle */
    handle->nfq_h = nfq_open();
    if (!handle->nfq_h) {
        fprintf(stderr, "Error: nfq_open() failed\n");
        free(handle);
        return NULL;
    }

    /* Unbind existing handler (if any) */
    if (nfq_unbind_pf(handle->nfq_h, AF_INET) < 0) {
        debug("nfq_unbind_pf AF_INET warning (usually OK): %s\n", strerror(errno));
    }
    if (nfq_unbind_pf(handle->nfq_h, AF_INET6) < 0) {
        debug("nfq_unbind_pf AF_INET6 warning (usually OK): %s\n", strerror(errno));
    }

    /* Bind to AF_INET and AF_INET6 */
    if (nfq_bind_pf(handle->nfq_h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_bind_pf(AF_INET) failed: %s\n", strerror(errno));
        nfq_close(handle->nfq_h);
        free(handle);
        return NULL;
    }
    if (nfq_bind_pf(handle->nfq_h, AF_INET6) < 0) {
        debug("nfq_bind_pf AF_INET6 warning: %s\n", strerror(errno));
        /* Not fatal — IPv6 support may not be available */
    }

    /* Create queue */
    handle->nfq_qh = nfq_create_queue(handle->nfq_h, queue_num, &nfq_pkt_callback, handle);
    if (!handle->nfq_qh) {
        fprintf(stderr, "Error: nfq_create_queue(%u) failed: %s\n", queue_num, strerror(errno));
        nfq_close(handle->nfq_h);
        free(handle);
        return NULL;
    }

    /* Set copy mode to copy entire packet */
    if (nfq_set_mode(handle->nfq_qh, NFQNL_COPY_PACKET, MAX_PACKET_SIZE) < 0) {
        fprintf(stderr, "Error: nfq_set_mode() failed\n");
        nfq_destroy_queue(handle->nfq_qh);
        nfq_close(handle->nfq_h);
        free(handle);
        return NULL;
    }

    /* Set maximum queue length */
    nfq_set_queue_maxlen(handle->nfq_qh, 8192);

    /* Increase netlink socket receive buffer size to prevent ENOBUFS
     * on high throughput connections */
    nfnl_rcvbufsiz(nfq_nfnlh(handle->nfq_h), 10485760);

    handle->fd = nfq_fd(handle->nfq_h);
    handle->running = 1;

    printf("NFQUEUE %u opened successfully\n", queue_num);
    return handle;
}

/**
 * Start the blocking receive loop.
 */
int nfqueue_loop(nfqueue_handle_t *handle) {
    char buf[MAX_PACKET_SIZE + 256];
    int rv;

    if (!handle)
        return -1;

    while (handle->running) {
        rv = recv(handle->fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(handle->nfq_h, buf, rv);
        }
        else {
            if (errno == EINTR)
                continue;
            if (errno == ENOBUFS) {
                /* Kernel buffer overflow. Drop packet and continue. */
                continue;
            }
            if (!handle->running)
                break;
            perror("nfqueue_loop: recv");
            return -1;
        }
    }

    return 0;
}

/**
 * Stop the NFQUEUE loop.
 */
void nfqueue_stop(nfqueue_handle_t *handle) {
    if (handle) {
        handle->running = 0;
    }
}

/**
 * Close the NFQUEUE handle and free resources.
 */
void nfqueue_close(nfqueue_handle_t *handle) {
    if (!handle)
        return;

    handle->running = 0;

    if (handle->nfq_qh) {
        nfq_destroy_queue(handle->nfq_qh);
        handle->nfq_qh = NULL;
    }
    if (handle->nfq_h) {
        nfq_close(handle->nfq_h);
        handle->nfq_h = NULL;
    }

    free(handle);
}
