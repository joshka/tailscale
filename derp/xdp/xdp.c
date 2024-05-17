//go:build ignore

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

// TODO: remove
char __license[] __attribute__((section("license"), used)) = "GPL";

struct config {
	__u16 dst_port;
};
struct config *unused_config __attribute__((unused));

struct bpf_map_def SEC("maps") config_map = {
      .type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(__u32),
      .value_size = sizeof(struct config),
      .max_entries = 1,
};

// TODO: stats map and enum

struct stunreq {
	__be16 type;
	__be16 length;
	__be32 magic;
	__be32 txid[3];
	// attributes follow
};

struct stunattr {
	__be16 num;
	__be16 length;
};

struct stunxor {
	__u8 unused;
	__u8 family;
	__be16 port;
	__be32 addr;
};

struct stunxor6 {
	__u8 unused;
	__u8 family;
	__be16 port;
	__be32 addr[4];
};

#define STUN_BINDING_REQUEST 1

#define STUN_MAGIC 0x2112a442

#define STUN_ATTR_SW 0x8022

#define STUN_ATTR_XOR_MAPPED_ADDR 0x0020

#define STUN_BINDING_RESPONSE 0x0101

#define STUN_MAGIC_FOR_PORT_XOR 0x2112

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	struct iphdr *ip;
	struct ipv6hdr *ip6;
	struct udphdr *udp;

	int is_ipv6;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		ip = (void *)(eth + 1);
    	if ((void *)(ip + 1) > data_end) {
    		return XDP_PASS;
    	}

    	if (ip->ihl != 5 || ip->version != 4 || ip->protocol != IPPROTO_UDP) {
    		return XDP_PASS;
    	}

		udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_PASS;
		}

		is_ipv6 = 0;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end) {
			return XDP_PASS;
		}

		if (ip6->version != 6 || ip6->nexthdr != IPPROTO_UDP) {
			return XDP_PASS;
		}

		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_PASS;
		}

		is_ipv6 = 1;
	} else {
		return XDP_PASS;
	}

	__u32 config_key = 0;
	struct config *c = bpf_map_lookup_elem(&config_map, &config_key);
	if (!c) {
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->dest) != c->dst_port) {
		return XDP_PASS;
	}

	struct stunreq *req = (void *)(udp + 1);
	if ((void *)(req + 1) > data_end) {
		return XDP_PASS;
	}

	if (bpf_ntohs(req->type) != STUN_BINDING_REQUEST) {
		return XDP_PASS;
	}
	if (bpf_ntohl(req->magic) != STUN_MAGIC) {
		return XDP_PASS;
	}

	void *attrs = (void *)(req + 1);
	__u16 attrs_len = ((char *)data_end) - ((char *)attrs);
	if (bpf_ntohs(req->length) != attrs_len) {
		return XDP_PASS;
	}

	struct stunattr *sa = attrs;
	if ((void *)(sa + 1) > data_end) {
		return XDP_PASS;
	}

	// Assume the order and contents of attributes. We *could* loop through
	// them, but parsing their lengths and performing arithmetic against the
	// packet pointer is more pain than it's worth. Bounds checks are invisible
	// to the verifier in certain circumstances where things move from registers
	// to the stack and/or compilation optimizations remove them entirely. There
	// have only ever been two attributes included by the client, and we are
	// only interested in one of them, anyway. Verify the software attribute,
	// but ignore the fingerprint attribute as it's only useful where STUN is
	// multiplexed with other traffic on the same port/socket, which is not the
	// case here.
	// TODO: remember to add test case to client documenting the attribute
	// assumptions made here.
	void *attr_data = (void *)(sa + 1);
	if (bpf_ntohs(sa->length) != 8 || bpf_ntohs(sa->num) != STUN_ATTR_SW) {
		return XDP_PASS;
	}
	if (attr_data + 8 > data_end) {
		return XDP_PASS;
	}
	char want_sw[] = {0x74, 0x61, 0x69, 0x6c, 0x6e, 0x6f, 0x64, 0x65}; // tailnode
	char *got_sw = attr_data;
	for (int j = 0; j < 8; j++) {
		if (got_sw[j] != want_sw[j]) {
			return XDP_PASS;
		}
	}

	// Begin transforming packet into a STUN_BINDING_RESPONSE. From here
	// onwards we return XDP_ABORTED instead of XDP_PASS when transformations or
	// bounds checks fail as it would be nonsensical to pass a mangled packet
	// through to the kernel.

	// Set success response and new length. Magic cookie and txid remain the
	// same.
	req->type = bpf_htons(STUN_BINDING_RESPONSE);
	if (is_ipv6) {
		req->length = bpf_htons(4 + 20); // stunattr + xor-mapped-addr attr (ipv6)
	} else {
		req->length = bpf_htons(4 + 8); // stunattr + xor-mapped-addr attr (ipv4)
	}

	// Set attr type. Length remains unchanged, but set it again for future
	// safety reasons.
	sa->num = bpf_htons(STUN_ATTR_XOR_MAPPED_ADDR);
	if (is_ipv6) {
		sa->length = bpf_htons(20);
	} else {
		sa->length = bpf_htons(8);
	}

	// Set attr data.
	struct stunxor *xor;
	struct stunxor6 *xor6;
	if (is_ipv6) {
		xor6 = attr_data;
		if ((void *)(xor6 + 1) > data_end) {
			int expand = (void *)(xor6 + 1) - data_end;
			if (bpf_xdp_adjust_tail(ctx, expand)) {
				return XDP_ABORTED;
			}
			data_end = (void *)(long)ctx->data_end;
			data = (void *)(long)ctx->data;
			eth = data;
			if ((void *)(eth + 1) > data_end) {
				return XDP_ABORTED;
			}
			ip6 = (void *)(eth + 1);
			if ((void *)(ip6 + 1) > data_end) {
				return XDP_ABORTED;
			}
			udp = (void *)(ip6 + 1);
			if ((void *)(udp + 1) > data_end) {
				return XDP_ABORTED;
			}
			req = (void *)(udp + 1);
			if ((void *)(req + 1) > data_end) {
				return XDP_PASS;
			}
			sa = (void *)(req + 1);
			if ((void *)(sa + 1) > data_end) {
				return XDP_ABORTED;
			}
			xor6 = (void *)(sa + 1);
			if ((void *)(xor6 + 1) > data_end) {
				return XDP_ABORTED;
			}
		}
		xor6->unused = 0x00; // unused byte
		xor6->family = 0x02;
		xor6->port = bpf_htons(bpf_ntohs(udp->source) ^ STUN_MAGIC_FOR_PORT_XOR);
		xor6->addr[0] = bpf_htonl(bpf_ntohl(ip6->saddr.in6_u.u6_addr32[0]) ^ STUN_MAGIC);
		for (int i = 1; i < 4; i++) {
			// All three are __be32, no endianness flips.
			xor6->addr[i] = ip6->saddr.in6_u.u6_addr32[i] ^ req->txid[i-1];
		}
	} else {
		xor = attr_data;
		if ((void *)(xor + 1) > data_end) {
			return XDP_ABORTED;
		}
		xor->unused = 0x00; // unused byte
		xor->family = 0x01;
		xor->port = bpf_htons(bpf_ntohs(udp->source) ^ STUN_MAGIC_FOR_PORT_XOR);
		xor->addr = bpf_htonl(bpf_ntohl(ip->saddr) ^ STUN_MAGIC);
	}

	// Flip ethernet header source and destination address.
	__u8 eth_tmp[ETH_ALEN];
	__builtin_memcpy(eth_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth_tmp, ETH_ALEN);

	// Flip ip header source and destination address.
	if (is_ipv6) {
		struct in6_addr ip_tmp = ip6->saddr;
		ip6->saddr = ip6->daddr;
		ip6->daddr = ip6->saddr;
	} else {
		__be32 ip_tmp = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = ip_tmp;
	}

	// Flip udp header source and destination ports;
	__be16 port_tmp = udp->source;
	udp->source = udp->dest;
	udp->dest = port_tmp;

	// Trim packet to end of xor stun attribute.
	if (is_ipv6) {
		int shrink = (void *)(xor6 + 1) - data_end;
		if (bpf_xdp_adjust_tail(ctx, shrink)) {
			return XDP_ABORTED;
		}
	} else {
		int shrink = (void *)(xor + 1) - data_end;
		if (bpf_xdp_adjust_tail(ctx, shrink)) {
			return XDP_ABORTED;
		}
	}

	// Reset pointers post tail adjustment.
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}
	if (is_ipv6) {
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end) {
			return XDP_ABORTED;
		}
	} else {
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			return XDP_ABORTED;
		}
	}

	// Update ip header total length field and checksum.
	__u32 cs = 0;
	if (is_ipv6) {
		if ((void *)(ip6 +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 payload_len = data_end - (void *)(ip6 + 1);
		ip6->payload_len = bpf_htons(payload_len);
	} else {
		__u16 tot_len = data_end - (void *)ip;
		ip->tot_len = bpf_htons(tot_len);
		ip->check = 0;
		cs = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), cs);
		ip->check = csum_fold_helper(cs);
	}

	// Avoid dynamic length math against the packet pointer, which is just a big
    // verifier headache. Instead sizeof() all the things.
	int to_csum_len = sizeof(*udp) + sizeof(*req) + sizeof(*sa);
	// Update udp header length and checksum.
	if (is_ipv6) {
		to_csum_len += sizeof(*xor6);
		udp = (void *)(ip6 + 1);
		if ((void *)(udp +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 udp_len = data_end - (void *)udp;
		udp->len = bpf_htons(udp_len);
		udp->check = 0;
		cs = 0;
		for (int i = 0;i < 8;i ++) {
			cs += ip6->saddr.in6_u.u6_addr16[i];
			cs += ip6->daddr.in6_u.u6_addr16[i];
		}
		cs += (__u16)ip6->nexthdr << 8;
		cs += udp->len;
	} else {
		to_csum_len += sizeof(*xor);
		udp = (void *)(ip + 1);
		if ((void *)(udp +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 udp_len = data_end - (void *)udp;
		udp->len = bpf_htons(udp_len);
		udp->check = 0;
		cs = 0;
		cs += (__u16)ip->saddr;
		cs += (__u16)(ip->saddr >> 16);
		cs += (__u16)ip->daddr;
		cs += (__u16)(ip->daddr >> 16);
		cs += (__u16)ip->protocol << 8;
		cs += udp->len;
	}
	if ((void *)udp + to_csum_len > data_end) {
		return XDP_ABORTED;
	}
	cs = bpf_csum_diff(0, 0, (void*)udp, to_csum_len, cs);
	udp->check = csum_fold_helper(cs);
	return XDP_TX;
}