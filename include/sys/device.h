#ifndef _WG_DEVICE_H
#define _WG_DEVICE_H

#include "noise.h"
#include "whitelist.h"
#include "peerlookup.h"
#include "cookie.h"

#include <sys/types.h>

struct wg_device;

struct multicore_worker {
	void *ptr;
	//struct work_struct work;
};

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

struct wg_device {
	struct noise_static_identity static_identity;
	struct index_hashtable *index_hashtable;
	struct pubkey_table *peer_hashtable;
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
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	unsigned int num_peers, device_update_gen;
	u32 fwmark;
	u16 incoming_port;
	bool have_creating_net_ref;
#endif
};

int wg_device_init(void);
void wg_device_uninit(void);

#endif /* _WG_DEVICE_H */
