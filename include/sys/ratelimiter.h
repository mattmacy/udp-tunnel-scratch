#ifndef _WG_RATELIMITER_H
#define _WG_RATELIMITER_H

#include <sys/mbuf.h>

struct net;

int wg_ratelimiter_init(void);
void wg_ratelimiter_uninit(void);
bool wg_ratelimiter_allow(struct mbuf *m, struct net *net);

#ifdef DEBUG
bool wg_ratelimiter_selftest(void);
#endif

#endif /* _WG_RATELIMITER_H */
