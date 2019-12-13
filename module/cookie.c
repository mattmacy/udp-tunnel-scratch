#include <sys/types.h>
#include <sys/sx.h>
#include <sys/libkern.h>
#include <sys/endian.h>

#include <sys/wg_module.h>
#include <sys/netmacros.h>
#include <sys/cookie.h>
#include <sys/socket.h>
#include <sys/peer.h>
#include <sys/messages.h>
#include <sys/ratelimiter.h>
#include <sys/timers.h>

#include <zinc/blake2s.h>
#include <zinc/chacha20poly1305.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

void
wg_cookie_checker_init(struct wg_cookie_checker *checker,
			    struct wg_softc *sc)
{
	sx_init(&checker->wcc_lock, "secret lock");
	checker->wcc_birthdate = gethrtime();
	arc4random_buf(checker->wcc_secret, NOISE_HASH_LEN);
	checker->wcc_sc = sc;
}

enum { COOKIE_KEY_LABEL_LEN = 8 };
static const uint8_t mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const uint8_t cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static void
precompute_key(uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN],
    const uint8_t label[COOKIE_KEY_LABEL_LEN])
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&blake, label, COOKIE_KEY_LABEL_LEN);
	blake2s_update(&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, key);
}

/* Must hold peer->handshake.static_identity->lock */
void
wg_cookie_checker_precompute_device_keys(struct wg_cookie_checker *checker)
{
	if (__predict_true(checker->wcc_sc->static_identity.has_identity)) {
		precompute_key(checker->wcc_encryption_key,
			       checker->wcc_sc->static_identity.static_public,
			       cookie_key_label);
		precompute_key(checker->message_mac1_key,
			       checker->wcc_sc->static_identity.static_public,
			       mac1_key_label);
	} else {
		memset(checker->wcc_encryption_key, 0,
		       NOISE_SYMMETRIC_KEY_LEN);
		memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
	}
}

void
wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	precompute_key(peer->latest_cookie.cookie_decryption_key,
		       peer->handshake.remote_static, cookie_key_label);
	precompute_key(peer->latest_cookie.message_mac1_key,
		       peer->handshake.remote_static, mac1_key_label);
}

void
wg_cookie_init(struct wg_cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
	sx_init(&cookie->lock, "cookie lock");
}

static void
compute_mac1(uint8_t mac1[COOKIE_LEN], const void *message, size_t len,
    const uint8_t key[NOISE_SYMMETRIC_KEY_LEN])
{
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac1);
	blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);
}

static void
compute_mac2(uint8_t mac2[COOKIE_LEN], const void *message, size_t len,
    const uint8_t cookie[COOKIE_LEN])
{
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac2);
	blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
}

static void
make_cookie(uint8_t cookie[COOKIE_LEN], struct mbuf *m,
    struct wg_cookie_checker *checker)
{
	struct blake2s_state state;
	uint16_t ether_type;

	if (wg_birthdate_has_expired(checker->wcc_birthdate,
				     COOKIE_SECRET_MAX_AGE)) {
		sx_xlock(&checker->wcc_lock);
		checker->wcc_birthdate = gethrtime();
		arc4random_buf(checker->wcc_secret, NOISE_HASH_LEN);
		sx_xunlock(&checker->wcc_lock);
	}

	sx_slock(&checker->wcc_lock);

	blake2s_init_key(&state, COOKIE_LEN, checker->wcc_secret, NOISE_HASH_LEN);
	ether_type = eh_type(m);
	if (ether_type == ETHERTYPE_IP)
		blake2s_update(&state, (uint8_t *)&ip_hdr(m)->ip_src,
			       sizeof(struct in_addr));
	else if (ether_type == ETHERTYPE_IPV6)
		blake2s_update(&state, (uint8_t *)&ip6_hdr(m)->ip6_src,
			       sizeof(struct in6_addr));
	blake2s_update(&state, (uint8_t *)&udp_hdr(m)->uh_sport, sizeof(uint16_t));
	blake2s_final(&state, cookie);

	sx_sunlock(&checker->wcc_lock);
}

enum cookie_mac_state
wg_cookie_validate_packet(struct wg_cookie_checker *checker,
    struct mbuf *m, bool check_cookie)
{
	struct message_macs *macs = (struct message_macs *)
		(m->m_data + m->m_len - sizeof(*macs));
	enum cookie_mac_state state;
	uint8_t computed_mac[COOKIE_LEN];
	uint8_t cookie[COOKIE_LEN];

	state = INVALID_MAC;
	compute_mac1(computed_mac, m->m_data, m->m_len,
		     checker->message_mac1_key);
	if (timingsafe_bcmp(computed_mac, macs->mac1, COOKIE_LEN))
		goto out;

	state = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	make_cookie(cookie, m, checker);

	compute_mac2(computed_mac, m->m_data, m->m_len, cookie);
	if (timingsafe_bcmp(computed_mac, macs->mac2, COOKIE_LEN))
		goto out;

	state = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
#ifdef notyet
	if (!wg_ratelimiter_allow(m, dev_net(checker->wcc_sc->dev)))
		goto out;
#endif
	state = VALID_MAC_WITH_COOKIE;

out:
	return (state);
}

void
wg_cookie_add_mac_to_packet(void *message, size_t len,
    struct wg_peer *peer)
{
	struct message_macs *macs = (struct message_macs *)
		((uint8_t *)message + len - sizeof(*macs));

	sx_xlock(&peer->latest_cookie.lock);
	compute_mac1(macs->mac1, message, len,
		     peer->latest_cookie.message_mac1_key);
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
	peer->latest_cookie.have_sent_mac1 = true;
	sx_xunlock(&peer->latest_cookie.lock);

	sx_slock(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid &&
	    !wg_birthdate_has_expired(peer->latest_cookie.birthdate,
				COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len,
			     peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);
	sx_sunlock(&peer->latest_cookie.lock);
}

void
wg_cookie_message_create(struct message_handshake_cookie *dst,
    struct mbuf *m, uint32_t index, struct wg_cookie_checker *checker)
{
	struct message_macs *macs = (struct message_macs *)
		((uint8_t *)m->m_data + m->m_len - sizeof(*macs));
	uint8_t cookie[COOKIE_LEN];

	dst->header.type = htole32(MESSAGE_HANDSHAKE_COOKIE);
	dst->receiver_index = index;
	arc4random_buf(dst->nonce, COOKIE_NONCE_LEN);

	make_cookie(cookie, m, checker);
	xchacha20poly1305_encrypt(dst->encrypted_cookie, cookie, COOKIE_LEN,
				  macs->mac1, COOKIE_LEN, dst->nonce,
				  checker->wcc_encryption_key);
}

void
wg_cookie_message_consume(struct message_handshake_cookie *src,
    struct wg_softc *sc)
{
	struct wg_peer *peer = NULL;
	uint8_t cookie[COOKIE_LEN];
	bool rc;

	if (__predict_false(!wg_index_hashtable_lookup(sc->index_hashtable,
						INDEX_HASHTABLE_HANDSHAKE |
						INDEX_HASHTABLE_KEYPAIR,
						src->receiver_index, &peer)))
		return;

	sx_slock(&peer->latest_cookie.lock);
	if (__predict_false(!peer->latest_cookie.have_sent_mac1)) {
		sx_sunlock(&peer->latest_cookie.lock);
		goto out;
	}
	rc = xchacha20poly1305_decrypt(
		cookie, src->encrypted_cookie, sizeof(src->encrypted_cookie),
		peer->latest_cookie.last_mac1_sent, COOKIE_LEN, src->nonce,
		peer->latest_cookie.cookie_decryption_key);
	sx_sunlock(&peer->latest_cookie.lock);

	if (rc) {
		sx_xlock(&peer->latest_cookie.lock);
		memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN);
		peer->latest_cookie.birthdate = gethrtime();
		peer->latest_cookie.is_valid = true;
		peer->latest_cookie.have_sent_mac1 = false;
		sx_xunlock(&peer->latest_cookie.lock);
	} else {
#ifdef notyet
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response\n",
				    sc->dev->name);
#endif
	}

out:
	wg_peer_put(peer);
}
