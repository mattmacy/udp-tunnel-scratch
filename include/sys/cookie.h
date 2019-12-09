#ifndef _WG_COOKIE_H
#define _WG_COOKIE_H

#include "messages.h"
#include <sys/sx.h>

struct wg_peer;

struct cookie_checker {
	uint8_t secret[NOISE_HASH_LEN];
	uint8_t cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	uint64_t secret_birthdate;
	struct sx secret_lock;
	struct wg_device *device;
};

struct cookie {
	uint64_t birthdate;
	bool is_valid;
	uint8_t cookie[COOKIE_LEN];
	bool have_sent_mac1;
	uint8_t last_mac1_sent[COOKIE_LEN];
	uint8_t cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	struct sx lock;
};

enum cookie_mac_state {
	INVALID_MAC,
	VALID_MAC_BUT_NO_COOKIE,
	VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
	VALID_MAC_WITH_COOKIE
};

void wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg);
void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker);
void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer);
void wg_cookie_init(struct cookie *cookie);

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie);
void wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer);

void wg_cookie_message_create(struct message_handshake_cookie *src,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker);
void wg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct wg_device *wg);

#endif /* _WG_COOKIE_H */
