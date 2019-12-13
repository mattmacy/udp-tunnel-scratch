#ifndef _WG_COOKIE_H
#define _WG_COOKIE_H

#include "messages.h"
#include <sys/sx.h>

struct wg_peer;

struct wg_cookie_checker {
	uint8_t wcc_secret[NOISE_HASH_LEN];
	uint8_t wcc_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	uint64_t wcc_birthdate;
	struct sx wcc_lock;
	struct wg_softc *wcc_sc;
};

struct wg_cookie {
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

void wg_cookie_checker_init(struct wg_cookie_checker *checker,
			    struct wg_softc *sc);
void wg_cookie_checker_precompute_device_keys(struct wg_cookie_checker *checker);
void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer);
void wg_cookie_init(struct wg_cookie *cookie);

enum cookie_mac_state wg_cookie_validate_packet(struct wg_cookie_checker *checker,
						struct mbuf *m,
						bool check_cookie);
void wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer);

void wg_cookie_message_create(struct message_handshake_cookie *src,
			      struct mbuf *m, uint32_t index,
			      struct wg_cookie_checker *checker);
void wg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct wg_softc *sc);

#endif /* _WG_COOKIE_H */
