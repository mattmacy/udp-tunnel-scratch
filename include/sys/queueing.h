#ifndef _WG_QUEUEING_H
#define _WG_QUEUEING_H

#include <sys/peer.h>
#include <sys/types.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct wg_device;
struct wg_peer;
struct multicore_worker;
struct crypt_queue;
struct mbuf;
struct work_struct;

/* queueing.c APIs: */
int wg_packet_queue_init(struct crypt_queue *queue, gtask_fn_t function,
			 bool multicore, unsigned int len);
void wg_packet_queue_free(struct crypt_queue *queue, bool multicore);
//struct multicore_worker /* __percpu */ *
//wg_packet_percpu_multicore_worker_alloc(gtask_fn_t function, void *ptr);

/* receive.c APIs: */
void wg_packet_receive(struct wg_device *wg, struct mbuf *m);
//void wg_packet_handshake_receive_worker(struct work_struct *work);
/* NAPI poll function: */
//int wg_packet_rx_poll(struct napi_struct *napi, int budget);
/* Workqueue worker: */
//void wg_packet_decrypt_worker(struct work_struct *work);

/* send.c APIs: */
void wg_packet_send_queued_handshake_initiation(struct wg_peer *peer,
						bool is_retry);
void wg_packet_send_handshake_response(struct wg_peer *peer);
void wg_packet_send_handshake_cookie(struct wg_device *wg,
				     struct mbuf *initiating_m,
				     uint32_t sender_index);
void wg_packet_send_keepalive(struct wg_peer *peer);
void wg_packet_purge_staged_packets(struct wg_peer *peer);
void wg_packet_send_staged_packets(struct wg_peer *peer);
#if 0
/* Workqueue workers: */
void wg_packet_handshake_send_worker(struct work_struct *work);
void wg_packet_tx_worker(struct work_struct *work);
void wg_packet_encrypt_worker(struct work_struct *work);
#endif
enum packet_state {
	PACKET_STATE_UNCRYPTED,
	PACKET_STATE_CRYPTED,
	PACKET_STATE_DEAD
};

struct packet_cb {
	uint64_t nonce;
	struct noise_keypair *keypair;
	volatile uint32_t state;
	uint32_t mtu;
	uint8_t ds;
};

//#define PACKET_CB(m) ((struct packet_cb *)((m)->cb))
//#define PACKET_PEER(m) (PACKET_CB(m)->keypair->entry.peer)
#if 0
static inline void wg_reset_packet(struct mbuf *m)
{
	const int pfmemalloc = m->pfmemalloc;

	m_scrub_packet(m, true);
	memset(&m->headers_start, 0,
	       offsetof(struct mbuf, headers_end) -
		       offsetof(struct mbuf, headers_start));
	m->pfmemalloc = pfmemalloc;
	m->queue_mapping = 0;
	m->nohdr = 0;
	m->peeked = 0;
	m->mac_len = 0;
	m->dev = NULL;
#ifdef CONFIG_NET_SCHED
	m->tc_index = 0;
	m_reset_tc(m);
#endif
	m->hdr_len = m_headroom(m);
	m_reset_mac_header(m);
	m_reset_network_header(m);
	m_reset_transport_header(m);
	m_probe_transport_header(m);
	m_reset_inner_headers(m);
}

static inline int wg_cpumask_choose_online(int *stored_cpu, unsigned int id)
{
	unsigned int cpu = *stored_cpu, cpu_index, i;

	if (__predict_false(cpu == nr_cpumask_bits ||
		     !cpumask_test_cpu(cpu, cpu_online_mask))) {
		cpu_index = id % cpumask_weight(cpu_online_mask);
		cpu = cpumask_first(cpu_online_mask);
		for (i = 0; i < cpu_index; ++i)
			cpu = cpumask_next(cpu, cpu_online_mask);
		*stored_cpu = cpu;
	}
	return cpu;
}

/* This function is racy, in the sense that next is unlocked, so it could return
 * the same CPU twice. A race-free version of this would be to instead store an
 * atomic sequence number, do an increment-and-return, and then iterate through
 * every possible CPU until we get to that index -- choose_cpu. However that's
 * a bit slower, and it doesn't seem like this potential race actually
 * introduces any performance loss, so we live with it.
 */
static inline int wg_cpumask_next_online(int *next)
{
	int cpu = *next;

	while (__predict_false(!cpumask_test_cpu(cpu, cpu_online_mask)))
		cpu = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	*next = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	return cpu;
}

static inline int wg_queue_enqueue_per_device_and_peer(
	struct crypt_queue *device_queue, struct crypt_queue *peer_queue,
	struct mbuf *m, struct workqueue_struct *wq, int *next_cpu)
{
	int cpu;

	atomic_set_release(&PACKET_CB(m)->state, PACKET_STATE_UNCRYPTED);
	/* We first queue this up for the peer ingestion, but the consumer
	 * will wait for the state to change to CRYPTED or DEAD before.
	 */
	if (__predict_false(ptr_ring_produce_bh(&peer_queue->ring, m)))
		return -ENOSPC;
	/* Then we queue it up in the device queue, which consumes the
	 * packet as soon as it can.
	 */
	cpu = wg_cpumask_next_online(next_cpu);
	if (__predict_false(ptr_ring_produce_bh(&device_queue->ring, m)))
		return -EPIPE;
	queue_work_on(cpu, wq, &per_cpu_ptr(device_queue->worker, cpu)->work);
	return 0;
}

static inline void wg_queue_enqueue_per_peer(struct crypt_queue *queue,
					     struct mbuf *m,
					     enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct wg_peer *peer = wg_peer_get(PACKET_PEER(m));

	atomic_set_release(&PACKET_CB(m)->state, state);
	queue_work_on(wg_cpumask_choose_online(&peer->serial_work_cpu,
					       peer->internal_id),
		      peer->device->packet_crypt_wq, &queue->work);
	wg_peer_put(peer);
}

static inline void wg_queue_enqueue_per_peer_napi(struct mbuf *m,
						  enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct wg_peer *peer = wg_peer_get(PACKET_PEER(m));

	atomic_set_release(&PACKET_CB(m)->state, state);
	//napi_schedule(&peer->napi);
	wg_peer_put(peer);
}
#endif
#ifdef DEBUG
bool wg_packet_counter_selftest(void);
#endif

#endif /* _WG_QUEUEING_H */
