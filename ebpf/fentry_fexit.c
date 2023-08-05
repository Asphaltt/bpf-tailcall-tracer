/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: MIT
 */

//go:build ignore

#include "bpf_all.h"

#include "lib_kprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} socks SEC(".maps");

SEC("kprobe/tailcall")
int fentry_tailcall(struct pt_regs *ctx)
{
    bpf_printk("tcpconn, fentry_tailcall, regs: %p\n", ctx);

    __u32 key = 0;
    struct sock **skp = bpf_map_lookup_elem(&socks, &key);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    __handle_new_connection(ctx, sk, PROBE_TYPE_FENTRY, 0);

    bpf_printk("tcpconn, fentry_tailcall, regs: %p, at end\n", ctx);

    return 0;
}

// SEC("fexit/tailcall")
// int BPF_PROG(fexit_tailcall, struct pt_regs *regs, int retval)
// {
//     bpf_printk("tcpconn, fexit_tailcall\n");

//     __u32 key = 0;
//     struct sock **skp = bpf_map_lookup_and_delete(&socks, &key);
//     if (!skp)
//         return 0;

//     struct sock *sk = *skp;
//     __handle_new_connection(ctx, sk, PROBE_TYPE_FEXIT, retval);

//     return 0;
// }

SEC("fentry/perf_event_output")
int BPF_PROG(fentry_perf_event_output, void *event, void *data, struct pt_regs * regs)
{
    bpf_printk("tcpconn, fentry_perf_event_output, regs: %p\n", regs); // regs: 0x0 after hack

    return 0;
}