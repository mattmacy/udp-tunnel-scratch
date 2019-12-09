/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_TIMERS_H
#define _WG_TIMERS_H

#include <linux/ktime.h>

struct wg_peer;

void wg_timers_init(struct wg_peer *peer);
void wg_timers_stop(struct wg_peer *peer);
void wg_timers_data_sent(struct wg_peer *peer);
void wg_timers_data_received(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_sent(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_received(struct wg_peer *peer);
void wg_timers_handshake_initiated(struct wg_peer *peer);
void wg_timers_handshake_complete(struct wg_peer *peer);
void wg_timers_session_derived(struct wg_peer *peer);
void wg_timers_any_authenticated_packet_traversal(struct wg_peer *peer);

static inline bool wg_birthdate_has_expired(uint64_t birthday_nanoseconds,
					    uint64_t expiration_seconds)
{
	return (int64_t)(birthday_nanoseconds + expiration_seconds * NSEC_PER_SEC)
		<= (int64_t)ktime_get_coarse_boottime_ns();
}

#endif /* _WG_TIMERS_H */
