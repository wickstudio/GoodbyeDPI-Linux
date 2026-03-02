#ifndef _NFQUEUE_H
#define _NFQUEUE_H

#include <stdint.h>
#include <stddef.h>

/* NFQUEUE queue numbers */
#define QUEUE_NUM_MAIN     200   /* Main queue for HTTP/HTTPS/DNS traffic */
#define QUEUE_NUM_PASSIVE  201   /* Queue for passive DPI blocking (RST drop) */
#define QUEUE_NUM_QUIC     202   /* Queue for QUIC blocking */

/* Verdict types */
#define VERDICT_ACCEPT  0
#define VERDICT_DROP    1

/* Packet direction */
#define PKT_DIR_OUTBOUND 1
#define PKT_DIR_INBOUND  0

/* Callback function type for packet processing */
typedef int (*nfqueue_callback_t)(
    int queue_id,
    unsigned char *packet_data,
    size_t packet_len,
    int is_outbound,
    void *user_data
);

/* NFQUEUE handle (opaque) */
typedef struct nfqueue_handle nfqueue_handle_t;

/**
 * Open an NFQUEUE and register a callback.
 * Returns a handle on success, NULL on failure.
 */
nfqueue_handle_t *nfqueue_open(uint16_t queue_num, nfqueue_callback_t callback, void *user_data);

/**
 * Start the blocking receive loop.
 * Returns when stopped or on error.
 */
int nfqueue_loop(nfqueue_handle_t *handle);

/**
 * Stop the NFQUEUE loop.
 */
void nfqueue_stop(nfqueue_handle_t *handle);

/**
 * Close the NFQUEUE handle and free resources.
 */
void nfqueue_close(nfqueue_handle_t *handle);

/**
 * Send a raw packet directly on the wire using AF_PACKET socket.
 * Used for injecting fake packets.
 */
int raw_socket_send(const char *packet, size_t packet_len);

/**
 * Initialize the raw socket for fake packet injection.
 * Must be called once before using raw_socket_send().
 */
int raw_socket_init(void);

/**
 * Close the raw socket.
 */
void raw_socket_close(void);

#endif /* _NFQUEUE_H */
