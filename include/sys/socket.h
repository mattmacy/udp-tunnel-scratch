#ifndef _WG_SOCKET_H
#define _WG_SOCKET_H

#include_next <sys/socket.h>

struct wg_softc;
struct wg_peer;
struct sock;
struct endpoint;

int wg_socket_init(struct wg_softc *sc, uint16_t port);
void wg_socket_reinit(struct wg_softc *sc, struct sock *new4,
		      struct sock *new6);
int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *data,
				  size_t len, uint8_t ds);
int wg_socket_send_m_to_peer(struct wg_peer *peer, struct mbuf *m,
			       uint8_t ds);
int wg_socket_send_buffer_as_reply_to_m(struct wg_softc *sc,
					  struct mbuf *in_m,
					  void *out_buffer, size_t len);

int wg_socket_endpoint_from_m(struct endpoint *endpoint,
				const struct mbuf *m);
void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_from_m(struct wg_peer *peer,
					  const struct mbuf *m);
void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer);

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_m_ratelimited(fmt, dev, m, ...) do {                       \
		struct endpoint __endpoint;                                    \
		wg_socket_endpoint_from_m(&__endpoint, m);                 \
		net_dbg_ratelimited(fmt, dev, &__endpoint.addr,                \
				    ##__VA_ARGS__);                            \
	} while (0)
#else
#define net_dbg_m_ratelimited(fmt, m, ...)
#endif

#endif /* _WG_SOCKET_H */
