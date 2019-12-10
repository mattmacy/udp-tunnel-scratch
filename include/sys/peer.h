#ifndef _WG_PEER_H
#define _WG_PEER_H

#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/device.h>
#include <sys/noise.h>
#include <sys/cookie.h>

#include <sys/types.h>


struct wg_device;

struct endpoint {
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	union {
		struct {
			struct in_addr src4;
			/* Essentially the same as addr6->scope_id */
			int src_if4;
		};
		struct in6_addr src6;
	};
};

struct wg_peer {
	struct wg_device *device;
	struct crypt_queue tx_queue, rx_queue;
	//struct sk_buff_head staged_packet_queue;
	int serial_work_cpu;
	struct noise_keypairs keypairs;
	struct endpoint endpoint;
	//struct dst_cache endpoint_cache;
	struct rwlock endpoint_lock;
	struct noise_handshake handshake;
	//atomic64_t last_sent_handshake;
	//struct work_struct transmit_handshake_work, clear_peer_work;
	struct cookie latest_cookie;
	//struct hlist_node pubkey_hash;
	uint64_t rx_bytes, tx_bytes;
	//struct timer_list timer_retransmit_handshake, timer_send_keepalive;
	//struct timer_list timer_new_handshake, timer_zero_key_material;
	//struct timer_list timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	uint16_t persistent_keepalive_interval;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct timespec walltime_last_handshake;
	//struct kref refcount;
	//struct rcu_head rcu;
	//struct list_head peer_list;
	//struct list_head allowedips_list;
	uint64_t internal_id;
	//struct napi_struct napi;
	bool is_dead;
};

struct wg_peer *wg_peer_create(struct wg_device *wg,
			       const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
			       const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

struct wg_peer *wg_peer_get_maybe_zero(struct wg_peer *peer);
static inline struct wg_peer *wg_peer_get(struct wg_peer *peer)
{
	//kref_get(&peer->refcount);
	panic("XXX");
	return peer;
}
void wg_peer_put(struct wg_peer *peer);
void wg_peer_remove(struct wg_peer *peer);
void wg_peer_remove_all(struct wg_device *wg);

#endif /* _WG_PEER_H */
