#include <sys/types.h>
#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/systm.h>
#include <machine/atomic.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/endian.h>
#include <sys/random.h>
#include <sys/kernel.h>

#include <sys/noise.h>
#include <sys/device.h>
#include <sys/socket.h>
#include <sys/peer.h>
#include <sys/messages.h>
#include <sys/wg_module.h>
//#include "queueing.h"
#include <sys/peerlookup.h>

#if 0
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <crypto/algapi.h>
#endif
/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

#define net_dbg_ratelimited(...)
CTASSERT(sizeof(char) == sizeof(bool));

static const uint8_t handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t identifier_name[30] = "WireGuard v1 FreeBSD.org";
static __read_mostly uint8_t handshake_init_hash[NOISE_HASH_LEN];
static __read_mostly uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];
//static atomic64_t keypair_counter = ATOMIC64_INIT(0);
static volatile uint64_t keypair_counter = 0;

void
wg_noise_init(void)
{
	struct blake2s_state blake;

	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash);
}

/* Must hold peer->handshake.static_identity->lock */
bool
wg_noise_precompute_static_static(struct wg_peer *peer)
{
	bool rc = true;

	sx_xlock(&peer->handshake.nh_lock);
	if (peer->handshake.static_identity->has_identity)
		rc = curve25519(
			peer->handshake.precomputed_static_static,
			peer->handshake.static_identity->static_private,
			peer->handshake.remote_static);
	else
		memset(peer->handshake.precomputed_static_static, 0,
		       NOISE_PUBLIC_KEY_LEN);
	sx_xunlock(&peer->handshake.nh_lock);
	return (rc);
}

bool
wg_noise_handshake_init(struct noise_handshake *handshake,
    struct noise_static_identity *static_identity,
    const uint8_t peer_public_key[NOISE_PUBLIC_KEY_LEN],
    const uint8_t peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
    struct wg_peer *peer)
{
	memset(handshake, 0, sizeof(*handshake));
	sx_init(&handshake->nh_lock, "handshake lock");
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;
	memcpy(handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
	if (peer_preshared_key)
		memcpy(handshake->preshared_key, peer_preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
	handshake->static_identity = static_identity;
	handshake->state = HANDSHAKE_ZEROED;
	return (wg_noise_precompute_static_static(peer));
}

static void
handshake_zero(struct noise_handshake *handshake)
{
	memset(&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->remote_index = 0;
	handshake->state = HANDSHAKE_ZEROED;
}

void
wg_noise_handshake_clear(struct noise_handshake *handshake)
{
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
	sx_xlock(&handshake->nh_lock);
	handshake_zero(handshake);
	sx_xunlock(&handshake->nh_lock);
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
}

static struct noise_keypair *
keypair_create(struct wg_peer *peer)
{
	struct noise_keypair *keypair;

	keypair = malloc(sizeof(*keypair), M_WG, M_NOWAIT|M_ZERO);
	if (__predict_false(!keypair))
		return (NULL);
	keypair->internal_id = atomic_fetchadd_64(&keypair_counter, 1) + 1;
	keypair->entry.type = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer = peer;
	refcount_init(&keypair->nk_refcount, 0);
	return (keypair);
}

static void
keypair_free_deferred(epoch_context_t ctx)
{
	struct noise_keypair *nk;

	nk = __containerof(ctx, struct noise_keypair, nk_epoch_ctx);
	free(nk, M_WG);
}

static void
noise_keypair_put_(struct noise_keypair *keypair)
{
	net_dbg_ratelimited("%s: Keypair %llu destroyed for peer %llu\n",
			    keypair->entry.peer->device->dev->name,
			    keypair->internal_id,
			    keypair->entry.peer->internal_id);
	wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable,
				  &keypair->entry);
	epoch_call(net_epoch, &keypair->nk_epoch_ctx, keypair_free_deferred);
}

void
wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now)
{
	if (__predict_false(!keypair))
		return;
	if (__predict_false(unreference_now))
		wg_index_hashtable_remove(
			keypair->entry.peer->device->index_hashtable,
			&keypair->entry);
	if (refcount_release(&keypair->nk_refcount))
		noise_keypair_put_(keypair);
}

struct noise_keypair *
wg_noise_keypair_get(struct noise_keypair *keypair)
{
#if 0
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
		"Taking noise keypair reference without holding the RCU BH read lock");
#endif
	if (__predict_false(!keypair || !refcount_acquire_if_not_zero(&keypair->nk_refcount)))
		return (NULL);
	return (keypair);
}

void
wg_noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;

	mtx_lock_spin(&keypairs->keypair_update_lock);

	/* We zero the next_keypair before zeroing the others, so that
	 * wg_noise_received_with_keypair returns early before subsequent ones
	 * are zeroed.
	 */
	old = keypairs->next_keypair;
	keypairs->next_keypair = NULL;
	wg_noise_keypair_put(old, true);

	old = keypairs->previous_keypair;
	keypairs->previous_keypair = NULL;
	wg_noise_keypair_put(old, true);

	old = keypairs->current_keypair;
	keypairs->current_keypair = NULL;
	wg_noise_keypair_put(old, true);

	mtx_unlock_spin(&keypairs->keypair_update_lock);
}

void
wg_noise_expire_current_peer_keypairs(struct wg_peer *peer)
{
	wg_noise_handshake_clear(&peer->handshake);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);

	mtx_lock_spin(&peer->keypairs.keypair_update_lock);
	if (peer->keypairs.next_keypair)
		peer->keypairs.next_keypair->sending.is_valid = false;
	if (peer->keypairs.current_keypair)
		peer->keypairs.current_keypair->sending.is_valid = false;
	mtx_unlock_spin(&peer->keypairs.keypair_update_lock);
}

static void
add_new_keypair(struct noise_keypairs *keypairs,
    struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;

	mtx_lock_spin(&keypairs->keypair_update_lock);
	previous_keypair = keypairs->previous_keypair;
	next_keypair = keypairs->next_keypair;
	current_keypair = keypairs->current_keypair;
	if (new_keypair->i_am_the_initiator) {
		/* If we're the initiator, it means we've sent a handshake, and
		 * received a confirmation response, which means this new
		 * keypair can now be used.
		 */
		if (next_keypair) {
			/* If there already was a next keypair pending, we
			 * demote it to be the previous keypair, and free the
			 * existing current. Note that this means KCI can result
			 * in this transition. It would perhaps be more sound to
			 * always just get rid of the unused next keypair
			 * instead of putting it in the previous slot, but this
			 * might be a bit less robust. Something to think about
			 * for the future.
			 */
			keypairs->next_keypair =  NULL;
			keypairs->previous_keypair = next_keypair;
			wg_noise_keypair_put(current_keypair, true);
		} else /* If there wasn't an existing next keypair, we replace
			* the previous with the current one.
			*/
			keypairs->previous_keypair = current_keypair;

		/* At this point we can get rid of the old previous keypair, and
		 * set up the new keypair.
		 */
		wg_noise_keypair_put(previous_keypair, true);
		keypairs->current_keypair = new_keypair;
	} else {
		/* If we're the responder, it means we can't use the new keypair
		 * until we receive confirmation via the first data packet, so
		 * we get rid of the existing previous one, the possibly
		 * existing next one, and slide in the new next one.
		 */
		keypairs->next_keypair = new_keypair;
		wg_noise_keypair_put(next_keypair, true);
		keypairs->previous_keypair = NULL;
		wg_noise_keypair_put(previous_keypair, true);
	}
	mtx_unlock_spin(&keypairs->keypair_update_lock);
}

bool
wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair)
{
	struct noise_keypair *old_keypair;

	if (__predict_true(received_keypair != keypairs->next_keypair))
		return (false);

	mtx_lock_spin(&keypairs->keypair_update_lock);
	/* After locking, we double check that things didn't change from
	 * beneath us.
	 */
	if (__predict_false(received_keypair != keypairs->next_keypair)) {
		mtx_unlock_spin(&keypairs->keypair_update_lock);
		return (false);
	}

	/* When we've finally received the confirmation, we slide the next
	 * into the current, the current into the previous, and get rid of
	 * the old previous.
	 */
	old_keypair = keypairs->previous_keypair;
	keypairs->previous_keypair = keypairs->current_keypair;
	wg_noise_keypair_put(old_keypair, true);
	keypairs->current_keypair = received_keypair;
	keypairs->next_keypair = NULL;

	mtx_unlock_spin(&keypairs->keypair_update_lock);
	return (true);
}

/* Must hold static_identity->lock */
void
wg_noise_set_static_identity_private_key(
	struct noise_static_identity *static_identity,
	const uint8_t private_key[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(static_identity->static_private, private_key,
	       NOISE_PUBLIC_KEY_LEN);
	curve25519_clamp_secret(static_identity->static_private);
	static_identity->has_identity = curve25519_generate_public(
		static_identity->static_public, private_key);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void
kdf(uint8_t *first_dst, uint8_t *second_dst, uint8_t *third_dst, const uint8_t *data,
		size_t first_len, size_t second_len, size_t third_len,
		size_t data_len, const uint8_t chaining_key[NOISE_HASH_LEN])
{
	uint8_t output[BLAKE2S_HASH_SIZE + 1];
	uint8_t secret[BLAKE2S_HASH_SIZE];

	/* Extract entropy from data into secret */
	blake2s_hmac(secret, data, chaining_key, BLAKE2S_HASH_SIZE, data_len,
		     NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE, 1,
		     BLAKE2S_HASH_SIZE);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_HASH_SIZE] = 2;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE,
		     BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_HASH_SIZE] = 3;
	blake2s_hmac(output, output, secret, BLAKE2S_HASH_SIZE,
		     BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	explicit_bzero(secret, BLAKE2S_HASH_SIZE);
	explicit_bzero(output, BLAKE2S_HASH_SIZE + 1);
}

static void
symmetric_key_init(struct noise_symmetric_key *key)
{
	mtx_init(&key->nsk_counter.receive.lock, "key receive lock", NULL, MTX_SPIN);
	atomic_store_rel_64(&key->nsk_counter.nc_counter, 0);
	memset(key->nsk_counter.receive.backtrack, 0,
	       sizeof(key->nsk_counter.receive.backtrack));
	key->birthdate = gethrtime();
	key->is_valid = true;
}

static void
derive_keys(struct noise_symmetric_key *first_dst,
    struct noise_symmetric_key *second_dst,
    const uint8_t chaining_key[NOISE_HASH_LEN])
{
	kdf(first_dst->key, second_dst->key, NULL, NULL,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
	    chaining_key);
	symmetric_key_init(first_dst);
	symmetric_key_init(second_dst);
}

static bool
mix_dh(uint8_t chaining_key[NOISE_HASH_LEN],
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t private[NOISE_PUBLIC_KEY_LEN],
    const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];

	if (__predict_false(!curve25519(dh_calculation, private, public)))
		return (false);
	kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	explicit_bzero(dh_calculation, NOISE_PUBLIC_KEY_LEN);
	return (true);
}

static void
mix_hash(uint8_t hash[NOISE_HASH_LEN], const uint8_t *src, size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

static void
mix_psk(uint8_t chaining_key[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
	uint8_t temp_hash[NOISE_HASH_LEN];

	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	explicit_bzero(temp_hash, NOISE_HASH_LEN);
}

static void
handshake_init(uint8_t chaining_key[NOISE_HASH_LEN],
    uint8_t hash[NOISE_HASH_LEN],
    const uint8_t remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void
message_encrypt(uint8_t *dst_ciphertext, const uint8_t *src_plaintext,
    size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    uint8_t hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
				 NOISE_HASH_LEN,
				 0 /* Always zero for Noise_IK */, key);
	mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static bool
message_decrypt(uint8_t *dst_plaintext, const uint8_t *src_ciphertext,
    size_t src_len, uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    uint8_t hash[NOISE_HASH_LEN])
{
	if (!chacha20poly1305_decrypt(dst_plaintext, src_ciphertext, src_len,
				      hash, NOISE_HASH_LEN,
				      0 /* Always zero for Noise_IK */, key))
		return (false);
	mix_hash(hash, src_ciphertext, src_len);
	return (true);
}

static void
message_ephemeral(uint8_t ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
    const uint8_t ephemeral_src[NOISE_PUBLIC_KEY_LEN],
    uint8_t chaining_key[NOISE_HASH_LEN],
    uint8_t hash[NOISE_HASH_LEN])
{
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
	    NOISE_PUBLIC_KEY_LEN, chaining_key);
}

#define rounddown_p2(n) (1UL << (flsl(n) - 1))

static void
tai64n_now(uint8_t output[NOISE_TIMESTAMP_LEN])
{
	struct timespec now;

	nanotime(&now);

	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = rounddown(now.tv_nsec,
		rounddown_p2(NANOSECOND / INITIATIONS_PER_SECOND));

	/* https://cr.yp.to/libtai/tai64.html */
	*(uint64_t *)output = htobe64(0x400000000000000aULL + now.tv_sec);
	*(uint32_t *)(output + sizeof(uint64_t)) = htobe32(now.tv_nsec);
}

bool
wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
				     struct noise_handshake *handshake)
{
	uint8_t timestamp[NOISE_TIMESTAMP_LEN];
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	bool rc = false;

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	while(!is_random_seeded())
		pause_sig("random seed", hz/10);

	sx_slock(&handshake->static_identity->nsi_lock);
	sx_xlock(&handshake->nh_lock);

	if (__predict_false(!handshake->static_identity->has_identity))
		goto out;

	dst->header.type = htole32(MESSAGE_HANDSHAKE_INITIATION);

	handshake_init(handshake->chaining_key, handshake->hash,
		       handshake->remote_static);

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, handshake->chaining_key,
			  handshake->hash);

	/* es */
	if (!mix_dh(handshake->chaining_key, key, handshake->ephemeral_private,
		    handshake->remote_static))
		goto out;

	/* s */
	message_encrypt(dst->encrypted_static,
			handshake->static_identity->static_public,
			NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

	/* ss */
	kdf(handshake->chaining_key, key, NULL,
	    handshake->precomputed_static_static, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	    handshake->chaining_key);

	/* {t} */
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp,
			NOISE_TIMESTAMP_LEN, key, handshake->hash);

	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_INITIATION;
	rc = true;

out:
	sx_xunlock(&handshake->nh_lock);
	sx_sunlock(&handshake->static_identity->nsi_lock);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	return (rc);
}

struct wg_peer *
wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src,
				      struct wg_device *wg)
{
	struct wg_peer *peer = NULL, *peer_result = NULL;
	struct noise_handshake *handshake;
	bool replay_attack, flood_attack;
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t hash[NOISE_HASH_LEN];
	uint8_t s[NOISE_PUBLIC_KEY_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	uint8_t t[NOISE_TIMESTAMP_LEN];
	uint64_t initiation_consumption;

	sx_slock(&wg->static_identity.nsi_lock);
	if (__predict_false(!wg->static_identity.has_identity))
		goto out;

	handshake_init(chaining_key, hash, wg->static_identity.static_public);

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* es */
	if (!mix_dh(chaining_key, key, wg->static_identity.static_private, e))
		goto out;

	/* s */
	if (!message_decrypt(s, src->encrypted_static,
			     sizeof(src->encrypted_static), key, hash))
		goto out;

	/* Lookup which peer we're actually talking to */
	peer = wg_pubkey_table_lookup(wg->peer_hashtable, s);
	if (!peer)
		goto out;
	handshake = &peer->handshake;

	/* ss */
	kdf(chaining_key, key, NULL, handshake->precomputed_static_static,
	    NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	    chaining_key);

	/* {t} */
	if (!message_decrypt(t, src->encrypted_timestamp,
			     sizeof(src->encrypted_timestamp), key, hash))
		goto out;

	sx_slock(&handshake->nh_lock);
	replay_attack = memcmp(t, handshake->latest_timestamp,
			       NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack = (int64_t)handshake->last_initiation_consumption +
			       NANOSECOND / INITIATIONS_PER_SECOND >
		(int64_t)gethrtime();
	sx_sunlock(&handshake->nh_lock);
	if (replay_attack || flood_attack)
		goto out;

	/* Success! Copy everything to peer */
	sx_xlock(&handshake->nh_lock);
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	if (memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
		memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	if ((int64_t)(handshake->last_initiation_consumption -
	    (initiation_consumption = gethrtime())) < 0)
		handshake->last_initiation_consumption = initiation_consumption;
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	sx_xunlock(&handshake->nh_lock);
	peer_result = peer;

out:
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(hash, NOISE_HASH_LEN);
	explicit_bzero(chaining_key, NOISE_HASH_LEN);
	sx_sunlock(&wg->static_identity.nsi_lock);
	if (!peer_result)
		wg_peer_put(peer);
	return (peer_result);
}

bool
wg_noise_handshake_create_response(struct message_handshake_response *dst,
					struct noise_handshake *handshake)
{
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	bool rc = false;

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	while(!is_random_seeded())
		pause_sig("random seed", hz/10);

	sx_slock(&handshake->static_identity->nsi_lock);
	sx_xlock(&handshake->nh_lock);

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	dst->header.type = htole32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->receiver_index = handshake->remote_index;

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, handshake->chaining_key,
			  handshake->hash);

	/* ee */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_ephemeral))
		goto out;

	/* se */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_static))
		goto out;

	/* psk */
	mix_psk(handshake->chaining_key, handshake->hash, key,
		handshake->preshared_key);

	/* {} */
	message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);

	dst->sender_index = wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry);

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	rc = true;

out:
	sx_xunlock(&handshake->nh_lock);
	sx_sunlock(&handshake->static_identity->nsi_lock);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	return (rc);
}

struct wg_peer *
wg_noise_handshake_consume_response(struct message_handshake_response *src,
				    struct wg_device *wg)
{
	enum noise_handshake_state state = HANDSHAKE_ZEROED;
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t hash[NOISE_HASH_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	uint8_t static_private[NOISE_PUBLIC_KEY_LEN];

	sx_slock(&wg->static_identity.nsi_lock);

	if (__predict_false(!wg->static_identity.has_identity))
		goto out;

	handshake = (struct noise_handshake *)wg_index_hashtable_lookup(
		wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE,
		src->receiver_index, &peer);
	if (__predict_false(!handshake))
		goto out;

	sx_slock(&handshake->nh_lock);
	state = handshake->state;
	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private,
	       NOISE_PUBLIC_KEY_LEN);
	sx_sunlock(&handshake->nh_lock);

	if (state != HANDSHAKE_CREATED_INITIATION)
		goto fail;

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* ee */
	if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
		goto fail;

	/* se */
	if (!mix_dh(chaining_key, NULL, wg->static_identity.static_private, e))
		goto fail;

	/* psk */
	mix_psk(chaining_key, hash, key, handshake->preshared_key);

	/* {} */
	if (!message_decrypt(NULL, src->encrypted_nothing,
			     sizeof(src->encrypted_nothing), key, hash))
		goto fail;

	/* Success! Copy everything to peer */
	sx_xlock(&handshake->nh_lock);
	/* It's important to check that the state is still the same, while we
	 * have an exclusive lock.
	 */
	if (handshake->state != state) {
		sx_xunlock(&handshake->nh_lock);
		goto fail;
	}
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	sx_xunlock(&handshake->nh_lock);
	ret_peer = peer;
	goto out;

fail:
	wg_peer_put(peer);
out:
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(hash, NOISE_HASH_LEN);
	explicit_bzero(chaining_key, NOISE_HASH_LEN);
	explicit_bzero(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	explicit_bzero(static_private, NOISE_PUBLIC_KEY_LEN);
	sx_sunlock(&wg->static_identity.nsi_lock);
	return ret_peer;
}

bool
wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs)
{
	struct noise_keypair *new_keypair;
	bool is_dead, rc = false;

	sx_xlock(&handshake->nh_lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
	    handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto out;

	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto out;
	new_keypair->i_am_the_initiator = handshake->state ==
					  HANDSHAKE_CONSUMED_RESPONSE;
	new_keypair->remote_index = handshake->remote_index;

	if (new_keypair->i_am_the_initiator)
		derive_keys(&new_keypair->sending, &new_keypair->receiving,
			    handshake->chaining_key);
	else
		derive_keys(&new_keypair->receiving, &new_keypair->sending,
			    handshake->chaining_key);

	handshake_zero(handshake);
	epoch_enter(net_epoch);
	is_dead = atomic_load_acq_char((char *)&__containerof(handshake, struct wg_peer,
											   handshake)->is_dead);
	if (__predict_true(!is_dead)) {
		add_new_keypair(keypairs, new_keypair);
		net_dbg_ratelimited("%s: Keypair %llu created for peer %llu\n",
				    handshake->entry.peer->device->dev->name,
				    new_keypair->internal_id,
				    handshake->entry.peer->internal_id);
		rc = wg_index_hashtable_replace(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry, &new_keypair->entry);
	}
	epoch_exit(net_epoch);
	/* need zero */
	if (is_dead)
		free(new_keypair, M_WG);
out:
	sx_xunlock(&handshake->nh_lock);
	return (rc);
}
