// Mirage per-process egress enforcement (cgroup v2, BPF_PROG_TYPE_CGROUP_SKB).
//
// SELF-CONTAINED: includes only <linux/bpf.h> + <linux/if_ether.h> and declares
// the few BPF helpers/macros it needs by hand — NO libbpf (bpf/bpf_helpers.h).
// This lets it compile with `clang -target bpf` in the canonical
// messense/rust-musl-cross image (clang + linux-libc-dev), which has no
// libbpf-dev. Loaded at runtime by the aya userspace loader in firewall.rs.
// (clang/C over aya-ebpf: avoids the nightly + bpf-linker + tier-3
// `bpfel-unknown-none` target chain; the BPF C ABI is the canonical surface.)
//
// Scope (T3): a single cgroup/skb EGRESS program = per-process kill-switch +
// raw-socket coverage. We do NOT install cgroup/connect4|6 redirectors: rewriting
// the destination to 127.0.0.1:<port> would destroy the original destination the
// existing nft REDIRECT path recovers via SO_ORIGINAL_DST. Wire capture stays on
// nft; eBPF only drops/passes per process at the IP output hook (also where
// SOCK_RAW egress is caught — the E2/E4 win).
//
// Plane tag (written into cgroup_plane_map by userspace):
//   BYPASS -> always PASS                 (invariant 1: bypass is sacred)
//   KILL   -> DROP all (except loopback)  (kill switch, covers raw sockets)
//   WIRE   -> PASS only egress out the TUN device or loopback; else DROP
//             (a wire-pinned process cannot leak natively, e.g. raw socket on a
//              physical NIC; legitimate chain traffic egresses the TUN device)
//   untracked cgroup -> PASS              (our own daemon + everything else)

#include <linux/bpf.h>
#include <linux/if_ether.h>

#define SEC(name) __attribute__((section(name), used))
#define bpf_htons(x) __builtin_bswap16(x)
// __always_inline is already provided by <linux/stddef.h>.

// libbpf-style BTF map macros (inlined so we don't need bpf/bpf_helpers.h).
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

// BPF helper function pointers — ids from the BPF_FUNC_* enum in <linux/bpf.h>.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_skb_cgroup_id)(struct __sk_buff *skb) =
    (void *)BPF_FUNC_skb_cgroup_id;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to, __u32 len) =
    (void *)BPF_FUNC_skb_load_bytes;

#define PLANE_BYPASS 0u
#define PLANE_WIRE   1u
#define PLANE_KILL   2u

// cgroup id (u64) -> plane tag (u32). Populated/cleared by userspace per process.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024);
} cgroup_plane_map SEC(".maps");

// cfg[0] = TUN ifindex (u32). Set once at activate().
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} cfg_map SEC(".maps");

// Returns 1 if the packet's destination is loopback (127/8 or ::1).
static __always_inline int dst_is_loopback(struct __sk_buff *skb)
{
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        __u32 d = 0;
        // IPv4 dst at offset 16 of the IP header (cgroup/skb egress data is L3).
        if (bpf_skb_load_bytes(skb, 16, &d, sizeof(d)) == 0)
            return (d & 0xff) == 127; // first network octet == 127
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        __u8 d6[16];
        // IPv6 dst at offset 24 of the IPv6 header.
        if (bpf_skb_load_bytes(skb, 24, d6, sizeof(d6)) == 0) {
            for (int i = 0; i < 15; i++)
                if (d6[i] != 0)
                    return 0;
            return d6[15] == 1; // ::1
        }
    }
    return 0;
}

SEC("cgroup_skb/egress")
int mirage_egress(struct __sk_buff *skb)
{
    __u64 cg = bpf_skb_cgroup_id(skb);
    __u32 *tag = bpf_map_lookup_elem(&cgroup_plane_map, &cg);
    if (!tag)
        return 1; // untracked process -> pass

    if (*tag == PLANE_BYPASS)
        return 1; // invariant 1: bypass is never dropped

    if (dst_is_loopback(skb))
        return 1; // local IPC / loopback always allowed

    if (*tag == PLANE_KILL)
        return 0; // kill: drop everything else (incl. raw sockets)

    // WIRE: allow only traffic egressing the TUN device; drop native leaks.
    __u32 k = 0;
    __u32 *tun_ifx = bpf_map_lookup_elem(&cfg_map, &k);
    if (tun_ifx && skb->ifindex == *tun_ifx)
        return 1;

    return 0; // wire native leak (e.g. raw socket on a physical NIC) -> drop
}

char _license[] SEC("license") = "GPL";
