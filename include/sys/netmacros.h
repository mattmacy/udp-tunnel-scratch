#ifndef _NETMACROS_H_
#define _NETMACROS_H_

#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/endian.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>


static inline uint16_t
eh_type(struct mbuf *m)
{
	struct ether_vlan_header *eh;
	uint16_t ether_type;

	eh =  mtod(m, struct ether_vlan_header *);

	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		ether_type = ntohs(eh->evl_proto);
	} else {
		ether_type = ntohs(eh->evl_encap_proto);
	}

	return (ether_type);
}

static inline uint16_t
eh_len(struct mbuf *m)
{
	struct ether_vlan_header *eh;
	uint16_t len;

	eh =  mtod(m, struct ether_vlan_header *);
	len = ETHER_HDR_LEN;
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		len += ETHER_VLAN_ENCAP_LEN;
	} 
	return (len);
}

static inline struct ip *
ip_hdr(struct mbuf *m)
{
	uint16_t offset;

	offset = eh_len(m);
	return ((struct ip *)(m->m_data + offset));
}

static inline struct ip6_hdr *
ip6_hdr(struct mbuf *m)
{
	uint16_t offset;

	offset = eh_len(m);
	return ((struct ip6_hdr *)(m->m_data + offset));
}

static inline uint16_t
ip_len(struct mbuf *m)
{
	uint16_t len;

	if (eh_type(m) == ETHERTYPE_IP)
		len = ip_hdr(m)->ip_hl << 2;
	else
		/* XXX doesn't take nested headers in to account*/
		len = sizeof(struct ip6_hdr); 
	return (len);
}

static inline struct udphdr *
udp_hdr(struct mbuf *m)
{
	return ((struct udphdr *)(m->m_data + eh_len(m) + ip_len(m)));
}



#endif
