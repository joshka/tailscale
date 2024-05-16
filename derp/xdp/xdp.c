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

	// TODO: ipv6

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

	// TODO: update udp payload
	// TODO: flip eth src/dst
	// TODO: flip ip src/dst
	// TODO: recalc UDP checksum
	// TODO: stats

	return XDP_DROP;
}