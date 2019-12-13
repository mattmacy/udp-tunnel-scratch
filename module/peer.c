#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/wg_module.h>

#include <sys/peer.h>
#include <sys/queueing.h>
#include <sys/timers.h>
#include <sys/peerlookup.h>
#include <sys/noise.h>


static volatile uint64_t peer_counter;

int
wg_peer_create(struct wg_softc *sc,
    const uint8_t public_key[NOISE_PUBLIC_KEY_LEN],
	const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN],
	struct wg_peer **ppeer)
{
	struct wg_peer *peer;
	int rc = ENOMEM;

	mtx_assert(&sc->device_update_lock, MA_OWNED);

	if (sc->wd_npeers >= MAX_PEERS_PER_DEVICE)
		return (rc);

	peer = malloc(sizeof(*peer), M_WG, M_ZERO|M_NOWAIT);
	if (__predict_false(peer == NULL))
		return (rc);
	peer->wp_sc = sc;

	if (!wg_noise_handshake_init(&peer->handshake, &sc->static_identity,
				     public_key, preshared_key, peer)) {
		rc = EINTEGRITY; /* key rejected */
		goto err_1;
	}
#if 0
	if (dst_cache_init(&peer->endpoint_cache, GFP_KERNEL))
		goto err_1;
	if (wg_packet_queue_init(&peer->tx_queue, wg_packet_tx_worker, false,
				 MAX_QUEUED_PACKETS))
		goto err_2;
	if (wg_packet_queue_init(&peer->rx_queue, NULL, false,
				 MAX_QUEUED_PACKETS))
		goto err_3;
#endif	

	peer->internal_id = atomic_fetchadd_64(&peer_counter, 1) + 1;
	peer->serial_work_cpu = mp_ncpus - 1;
	wg_cookie_init(&peer->latest_cookie);
	wg_timers_init(peer);
	wg_cookie_checker_precompute_peer_keys(peer);
	mtx_init(&peer->keypairs.keypair_update_lock, "keypair update", NULL, MTX_SPIN);
	//	INIT_WORK(&peer->transmit_handshake_work,
	//wg_packet_handshake_send_worker);
	rw_init(&peer->endpoint_lock, "endpoint");
	refcount_init(&peer->wp_refcount, 0);
	//skb_queue_head_init(&peer->staged_packet_queue);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	//set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	//netif_napi_add(sc->dev, &peer->napi, wg_packet_rx_poll,
	//	       NAPI_POLL_WEIGHT);
	//api_enable(&peer->napi);
	CK_STAILQ_INSERT_TAIL(&sc->wd_peer_list, peer, wp_entry);
	CK_LIST_INIT(&peer->wp_whitelist);
	wg_pubkey_table_add(sc->peer_hashtable, peer);
	++sc->wd_npeers;
	//pr_debug("%s: Peer %llu created\n", sc->dev->name, peer->internal_id);
	*ppeer = peer;
	return (0);

	//err_3:
	wg_packet_queue_free(&peer->tx_queue, false);
	//err_2:
	//dst_cache_destroy(&peer->endpoint_cache);
err_1:
	free(peer, M_WG);
	return (rc);
}

struct wg_peer *
wg_peer_get_maybe_zero(struct wg_peer *peer)
{
#if 0
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
#endif
	if (__predict_false(peer == NULL || !refcount_acquire_if_not_zero(&peer->wp_refcount)))
		return (NULL);
	return (peer);
}

static void
peer_make_dead(struct wg_peer *peer)
{
	/* Remove from configuration-time lookup structures. */
	CK_STAILQ_REMOVE(&peer->wp_sc->wd_peer_list, peer, wg_peer, wp_entry);
	wg_whitelist_remove_by_peer(&peer->wp_sc->wd_whitelist, peer,
				     &peer->wp_sc->device_update_lock);
	wg_pubkey_table_remove(peer->wp_sc->peer_hashtable, peer);

	/* Mark as dead, so that we don't allow jumping contexts after. */
	atomic_store_rel_char((char *)&peer->is_dead, true);

	/* The caller must now synchronize_rcu() for this to take effect. */
}

static void
peer_remove_after_dead(struct wg_peer *peer)
{
	MPASS(peer->is_dead);

	/* No more keypairs can be created for this peer, since is_dead protects
	 * add_new_keypair, so we can now destroy existing ones.
	 */
	wg_noise_keypairs_clear(&peer->keypairs);

	/* Destroy all ongoing timers that were in-flight at the beginning of
	 * this function.
	 */
	wg_timers_stop(peer);

	/* The transition between packet encryption/decryption queues isn't
	 * guarded by is_dead, but each reference's life is strictly bounded by
	 * two generations: once for parallel crypto and once for serial
	 * ingestion, so we can simply flush twice, and be sure that we no
	 * longer have references inside these queues.
	 */
#if 0
	
	/* a) For encrypt/decrypt. */
	flush_workqueue(peer->wp_sc->packet_crypt_wq);
	/* b.1) For send (but not receive, since that's napi). */
	flush_workqueue(peer->wp_sc->packet_crypt_wq);
	/* b.2.1) For receive (but not send, since that's wq). */
	napi_disable(&peer->napi);
	/* b.2.1) It's now safe to remove the napi struct, which must be done
	 * here from process context.
	 */
	netif_napi_del(&peer->napi);

	/* Ensure any workstructs we own (like transmit_handshake_work or
	 * clear_peer_work) no longer are in use.
	 */
	flush_workqueue(peer->wp_sc->handshake_send_wq);
#endif
	
	/* After the above flushes, a peer might still be active in a few
	 * different contexts: 1) from xmit(), before hitting is_dead and
	 * returning, 2) from wg_packet_consume_data(), before hitting is_dead
	 * and returning, 3) from wg_receive_handshake_packet() after a point
	 * where it has processed an incoming handshake packet, but where
	 * all calls to pass it off to timers fails because of is_dead. We won't
	 * have new references in (1) eventually, because we're removed from
	 * whitelist; we won't have new references in (2) eventually, because
	 * wg_index_hashtable_lookup will always return NULL, since we removed
	 * all existing keypairs and no more can be created; we won't have new
	 * references in (3) eventually, because we're removed from the pubkey
	 * hash table, which allows for a maximum of one handshake response,
	 * via the still-uncleared index hashtable entry, but not more than one,
	 * and in wg_cookie_message_consume, the lookup eventually gets a peer
	 * with a refcount of zero, so no new reference is taken.
	 */

	--peer->wp_sc->wd_npeers;
	wg_peer_put(peer);
}

/* We have a separate "remove" function make sure that all active places where
 * a peer is currently operating will eventually come to an end and not pass
 * their reference onto another context.
 */
void
wg_peer_remove(struct wg_peer *peer)
{
	if (__predict_false(!peer))
		return;
	mtx_assert(&peer->wp_sc->device_update_lock, MA_OWNED);

	peer_make_dead(peer);
	epoch_wait(net_epoch);
	peer_remove_after_dead(peer);
}

void
wg_peer_remove_all(struct wg_softc *sc)
{
	struct wg_peer *peer;
	CK_STAILQ_HEAD(, wg_peer) dead_peers;

	CK_STAILQ_INIT(&dead_peers);
	mtx_assert(&peer->wp_sc->device_update_lock, MA_OWNED);
	
	/* Avoid having to traverse individually for each one. */
	wg_whitelist_free(&sc->wd_whitelist, &sc->device_update_lock);

	while (!CK_STAILQ_EMPTY(&sc->wd_peer_list)) {
		peer = CK_STAILQ_FIRST(&sc->wd_peer_list);
		peer_make_dead(peer);
		CK_STAILQ_INSERT_TAIL(&dead_peers, peer, wp_entry);
	}
	epoch_wait(net_epoch);
	while (!CK_STAILQ_EMPTY(&dead_peers)) {
		peer = CK_STAILQ_FIRST(&dead_peers);
		CK_STAILQ_REMOVE_HEAD(&dead_peers, wp_entry);
		peer_remove_after_dead(peer);
	}
}

static void
wg_peer_free_deferred(epoch_context_t ctx)
{
	struct wg_peer *peer;

	peer = __containerof(ctx, struct wg_peer, wp_epoch_ctx);

	//dst_cache_destroy(&peer->endpoint_cache);
	//wg_packet_queue_free(&peer->rx_queue, false);
	//wg_packet_queue_free(&peer->tx_queue, false);

	/* The final zeroing takes care of clearing any remaining handshake key
	 * material and other potentially sensitive information.
	 */
	zfree(peer, M_WG);
}

static void
wg_peer_put_(struct wg_peer *peer)
{

#if 0	
	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->wp_sc->dev->name, peer->internal_id,
		 &peer->endpoint.addr);
#endif
	/* Remove ourself from dynamic runtime lookup structures, now that the
	 * last reference is gone.
	 */
	wg_index_hashtable_remove(peer->wp_sc->index_hashtable,
				  &peer->handshake.nh_entry);

	/* Remove any lingering packets that didn't have a chance to be
	 * transmitted.
	 */
	wg_packet_purge_staged_packets(peer);

	/* Free the memory used. */
	epoch_call(net_epoch, &peer->wp_epoch_ctx, wg_peer_free_deferred);
}

void
wg_peer_put(struct wg_peer *peer)
{
	if (__predict_false(!peer))
		return;
	if (__predict_false(refcount_release(&peer->wp_refcount)))
		wg_peer_put_(peer);
}
