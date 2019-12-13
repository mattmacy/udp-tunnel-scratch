#ifndef MODULE_H_
#define MODULE_H_

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>

#include <net/iflib.h>

#include <sys/whitelist.h>
#include <sys/noise.h>

MALLOC_DECLARE(M_WG);
#define zfree(addr, type)						\
	do {										\
		explicit_bzero(addr, sizeof(*addr));	\
		free(addr, type);						\
	} while (0)

struct crypt_queue {
	//struct ptr_ring ring;
	union {
		struct {
			//struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		//struct work_struct work;
	};
};

struct wg_softc {
	if_softc_ctx_t shared;
	if_ctx_t wg_ctx;
	struct ifnet *wg_ifp;

	struct noise_static_identity static_identity;
	struct index_hashtable *index_hashtable;
	struct pubkey_table *peer_hashtable;
	struct mtx device_update_lock, socket_update_lock;
	unsigned int wd_npeers, wd_gen;
	CK_STAILQ_HEAD(, wg_peer) wd_peer_list;
	struct whitelist wd_whitelist;
	//struct list_head device_list, peer_list;

#if 0
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue;
	struct sock __rcu *sock4, *sock6;
	struct net *creating_net;
	struct workqueue_struct *handshake_receive_wq, *handshake_send_wq;
	struct workqueue_struct *packet_crypt_wq;
	struct sk_buff_head incoming_handshakes;
	int incoming_handshake_cpu;
	struct multicore_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct allowedips peer_allowedips;
	u32 fwmark;
	u16 incoming_port;
	bool have_creating_net_ref;
#endif
};

int wg_ctx_init(void);
void wg_ctx_uninit(void);


#endif
