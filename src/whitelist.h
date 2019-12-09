#ifndef _WG_WHITELIST_H
#define _WG_WHITELIST_H

#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wg_peer;

struct whitelist_node {
	struct wg_peer  *peer;
	u8 bits[16] __aligned(__alignof(uint64_t));
	u8 cidr, bit_at_a, bit_at_b, bitlen;
	union {
		struct list_head peer_list;
		struct rcu_head rcu;
	};
};

struct whitelist {
	struct whitelist_node  *root4;
	struct whitelist_node  *root6;
	u64 seq;
};

void wg_whitelist_init(struct whitelist *table);
void wg_whitelist_free(struct whitelist *table, struct mutex *mutex);
int wg_whitelist_insert_v4(struct whitelist *table, const struct in_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock);
int wg_whitelist_insert_v6(struct whitelist *table, const struct in6_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock);
void wg_whitelist_remove_by_peer(struct whitelist *table,
				  struct wg_peer *peer, struct mutex *lock);
int wg_whitelist_read_node(struct whitelist_node *node, u8 ip[16], u8 *cidr);

/* These return a strong reference to a peer: */
struct wg_peer *wg_whitelist_lookup_dst(struct whitelist *table,
					 struct mbuf *skb);
struct wg_peer *wg_whitelist_lookup_src(struct whitelist *table,
					 struct mbuf *skb);

#ifdef DEBUG
bool wg_whitelist_selftest(void);
#endif

#endif /* _WG_WHITELIST_H */
