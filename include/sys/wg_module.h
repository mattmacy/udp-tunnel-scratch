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

/*
 * Workaround FreeBSD's shitty typed atomic
 * accessors
 */
#define __ATOMIC_LOAD_SIZE						\
	({									\
	switch (size) {							\
	case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;		\
	case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;		\
	case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;		\
	case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;		\
	}								\
})

static inline void
__atomic_load_acq_size(volatile void *p, void *res, int size)
{
	__ATOMIC_LOAD_SIZE;
}

#define atomic_load_acq(x)						\
	({											\
	union { __typeof(x) __val; char __c[1]; } __u;			\
	__atomic_load_acq_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;												\
})

struct wg_softc {
	if_softc_ctx_t shared;
	if_ctx_t wg_ctx;
	struct ifnet *wg_ifp;

	struct noise_static_identity static_identity;
	struct index_hashtable *index_hashtable;
	struct pubkey_table *peer_hashtable;
	struct mtx wg_socket_lock;
	unsigned int wg_npeers, wg_gen;
	CK_STAILQ_HEAD(, wg_peer) wg_peer_list;
	struct whitelist wg_whitelist;
	//struct list_head device_list, peer_list;
	struct socket *wg_sock4;
	struct socket *wg_sock6;
	

#if 0
	struct crypt_queue encrypt_queue, decrypt_queue;
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
