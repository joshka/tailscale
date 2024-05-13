//go:build ignore

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
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

struct stunreq {
	__be16 type;
	__be16 length;
	__be32 magic;
	__u8 txid[12];
	// attributes follow
};

struct stunattr {
	__be16 num;
	__be16 length;
};

#define STUN_BINDING_REQUEST 1

#define STUN_MAGIC 0x2112a442

#define STUN_ATTR_SW 0x8022

// We don't expect more than 2 from our own client at time of authorship, this
// is somewhat arbitrary. We leave room in case new attributes are added later,
// but we keep it bounded for performance & verifier reasons.
#define STUN_MAX_ATTRS 16

#define STUN_MAX_ATTR_LEN 1500 - 40 - 8 - 20 - 4 // MTU - ipv6hdr - udphdr - stunhdr - stunattrhdr

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	if (ip->ihl != 5 || ip->version != 4 || ip->protocol != IPPROTO_UDP) {
		return XDP_PASS;
	}

	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end) {
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
	// We can probably assume eBPF bounded loops (Linux 5.3) are available, but
	// unroll to be safe to allow an older kernel version to be a potential
	// build target.
	#pragma clang loop unroll(full)
	for (int i = 0; i < STUN_MAX_ATTRS; i++) {
		if ((void *)(sa + 1) > data_end) {
			return XDP_PASS;
		}

		void *attr_data = (void *)(sa + 1);
		__u16 attr_data_len = bpf_ntohs(sa->length);
		// TODO: attrs are padded to multiple of 4

		// The following exists solely to satisfy the verifier. Without it we
		// get an error from the verifier: "math between pkt pointer and
		// register with unbounded min value is not allowed" in reference to
		// attr_data (register holding packet pointer) + attr_data_len (register
		// w/o min bound).
		if (attr_data_len > STUN_MAX_ATTR_LEN) {
			return XDP_PASS;
		}

		// Not a required bounds check from a verifier perspective, but we
		// require all attrs to have valid lengths, even if we don't verify
		// their contents.
		if (attr_data + attr_data_len > data_end) {
			return XDP_PASS;
		}

		// Verify software STUN attribute. Clients also include a fingerprint
		// attribute, but we don't require or validate it. The fingerprint
		// attribute exists to help software distinguish STUN packets from other
		// protocols when they are multiplexed on the same port/socket. This is
		// needed on the client side, but on the server we only serve STUN on
		// the configured UDP port.
		if (bpf_ntohs(sa->num) == STUN_ATTR_SW) {
			if (attr_data_len != 8) {
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
			break;
		}

		// advance sa by its own length
		sa += 1;
		// advance sa by the length of last attr's data
		sa = ((void *)sa) + attr_data_len;
	}

	// TODO: update udp payload
	// TODO: flip eth src/dst
	// TODO: flip ip src/dst
	// TODO: recalc UDP checksum
	// TODO: stats

	return XDP_DROP;
}